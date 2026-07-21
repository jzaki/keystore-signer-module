//! Per-namespace, encrypted-at-rest key persistence.
//!
//! Layout on disk: `<root>/<namespace_id>/<key_id>.key`, where each `.key`
//! file is `algorithm_tag(1) || nonce(12) || ChaCha20-Poly1305(secret_bytes)`.
//! The AEAD key is HKDF-SHA256(secret, "keystore_signer storage key v1") —
//! derived from the same bearer secret that gates namespace lookup, so a
//! compromise of the on-disk `root` directory alone (without any caller's
//! secret) yields only ciphertext.

use std::fs;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore as _;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::algorithms::{self, Algorithm, KeyMaterial};
use crate::registry::{self, namespace_id};

const NONCE_LEN: usize = 12;
const HKDF_INFO: &[u8] = b"keystore_signer storage key v1";

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Namespace(#[from] registry::Error),
    #[error(transparent)]
    Algorithm(#[from] algorithms::Error),
    #[error("key not found")]
    KeyNotFound,
    #[error("stored key is corrupt or was tampered with")]
    Corrupt,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Storage {
    root: PathBuf,
}

impl Storage {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn namespace_dir(&self, secret: &[u8]) -> Result<PathBuf, Error> {
        Ok(self.root.join(namespace_id(secret)?))
    }

    fn derive_cipher(secret: &[u8]) -> ChaCha20Poly1305 {
        let hk = Hkdf::<Sha256>::new(None, secret);
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        hk.expand(HKDF_INFO, &mut *key_bytes)
            .expect("32 bytes is a valid HKDF-SHA256 and ChaCha20Poly1305 key length");
        ChaCha20Poly1305::new(Key::from_slice(&key_bytes[..]))
    }

    pub fn create_key(&self, secret: &[u8], algorithm: Algorithm) -> Result<(String, Vec<u8>), Error> {
        let dir = self.namespace_dir(secret)?;
        fs::create_dir_all(&dir)?;

        let key = KeyMaterial::generate(algorithm);
        let public_key = key.public_key_bytes();
        let key_id = new_key_id();
        self.seal(&dir, &key_id, secret, algorithm, &key)?;

        Ok((key_id, public_key))
    }

    fn seal(
        &self,
        dir: &Path,
        key_id: &str,
        secret: &[u8],
        algorithm: Algorithm,
        key: &KeyMaterial,
    ) -> Result<(), Error> {
        let cipher = Self::derive_cipher(secret);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let secret_bytes = key.secret_bytes();
        let ciphertext = cipher
            .encrypt(nonce, secret_bytes.as_slice())
            .expect("encrypting an in-memory buffer with a freshly derived key cannot fail");

        let mut blob = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        blob.push(algorithm_tag(algorithm));
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);

        fs::write(dir.join(format!("{key_id}.key")), blob)?;
        Ok(())
    }

    fn open(&self, dir: &Path, key_id: &str, secret: &[u8]) -> Result<KeyMaterial, Error> {
        let blob = fs::read(dir.join(format!("{key_id}.key"))).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::KeyNotFound
            } else {
                Error::Io(e)
            }
        })?;
        if blob.len() < 1 + NONCE_LEN {
            return Err(Error::Corrupt);
        }
        let algorithm = algorithm_from_tag(blob[0]).ok_or(Error::Corrupt)?;
        let nonce = Nonce::from_slice(&blob[1..1 + NONCE_LEN]);
        let ciphertext = &blob[1 + NONCE_LEN..];

        let cipher = Self::derive_cipher(secret);
        // Reaching here already required deriving the right namespace_dir
        // from `secret`, i.e. already having the right secret — a decrypt
        // failure at this point means on-disk corruption/tampering, not a
        // wrong secret (a wrong secret would have missed the directory
        // entirely, several lines above).
        let secret_bytes = cipher.decrypt(nonce, ciphertext).map_err(|_| Error::Corrupt)?;
        Ok(KeyMaterial::from_secret_bytes(algorithm, &secret_bytes)?)
    }

    pub fn public_key(&self, secret: &[u8], key_id: &str) -> Result<Vec<u8>, Error> {
        let dir = self.namespace_dir(secret)?;
        Ok(self.open(&dir, key_id, secret)?.public_key_bytes())
    }

    pub fn sign(&self, secret: &[u8], key_id: &str, message: &[u8]) -> Result<Vec<u8>, Error> {
        let dir = self.namespace_dir(secret)?;
        Ok(self.open(&dir, key_id, secret)?.sign(message))
    }

    pub fn list_keys(&self, secret: &[u8]) -> Result<Vec<String>, Error> {
        let dir = self.namespace_dir(secret)?;
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(Error::Io(e)),
        };

        let mut ids = Vec::new();
        for entry in entries {
            let entry = entry?;
            if let Some(id) = entry.file_name().to_str().and_then(|n| n.strip_suffix(".key")) {
                ids.push(id.to_string());
            }
        }
        ids.sort();
        Ok(ids)
    }

    pub fn delete_key(&self, secret: &[u8], key_id: &str) -> Result<bool, Error> {
        // Locating the namespace directory already requires `secret` — that
        // is the isolation boundary; deleting doesn't need to decrypt.
        let dir = self.namespace_dir(secret)?;
        match fs::remove_file(dir.join(format!("{key_id}.key"))) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::Io(e)),
        }
    }
}

fn algorithm_tag(algorithm: Algorithm) -> u8 {
    match algorithm {
        Algorithm::Ed25519 => 1,
        Algorithm::Secp256k1 => 2,
        Algorithm::Bls12_381 => 3,
    }
}

fn algorithm_from_tag(tag: u8) -> Option<Algorithm> {
    match tag {
        1 => Some(Algorithm::Ed25519),
        2 => Some(Algorithm::Secp256k1),
        3 => Some(Algorithm::Bls12_381),
        _ => None,
    }
}

fn new_key_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_storage() -> (Storage, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (Storage::new(dir.path()), dir)
    }

    const SECRET_A: [u8; 32] = [1u8; 32];
    const SECRET_B: [u8; 32] = [2u8; 32];

    #[test]
    fn create_sign_verify_round_trip() {
        let (storage, _dir) = tmp_storage();
        let (key_id, public_key) = storage.create_key(&SECRET_A, Algorithm::Ed25519).unwrap();

        let msg = b"payload";
        let sig = storage.sign(&SECRET_A, &key_id, msg).unwrap();
        assert!(algorithms::verify(Algorithm::Ed25519, &public_key, msg, &sig).unwrap());

        assert_eq!(storage.public_key(&SECRET_A, &key_id).unwrap(), public_key);
    }

    #[test]
    fn list_keys_only_shows_own_namespace() {
        let (storage, _dir) = tmp_storage();
        let (id_a, _) = storage.create_key(&SECRET_A, Algorithm::Ed25519).unwrap();
        let (id_b, _) = storage.create_key(&SECRET_B, Algorithm::Secp256k1).unwrap();

        assert_eq!(storage.list_keys(&SECRET_A).unwrap(), vec![id_a]);
        assert_eq!(storage.list_keys(&SECRET_B).unwrap(), vec![id_b]);
    }

    #[test]
    fn other_caller_cannot_sign_with_a_different_namespaces_key() {
        let (storage, _dir) = tmp_storage();
        let (key_id, _) = storage.create_key(&SECRET_A, Algorithm::Ed25519).unwrap();

        // B doesn't even find A's key — it lives under a different directory.
        let err = storage.sign(&SECRET_B, &key_id, b"forged").unwrap_err();
        assert!(matches!(err, Error::KeyNotFound));
    }

    #[test]
    fn other_caller_cannot_read_public_key_or_delete() {
        let (storage, _dir) = tmp_storage();
        let (key_id, _) = storage.create_key(&SECRET_A, Algorithm::Ed25519).unwrap();

        assert!(matches!(
            storage.public_key(&SECRET_B, &key_id).unwrap_err(),
            Error::KeyNotFound
        ));
        assert_eq!(storage.delete_key(&SECRET_B, &key_id).unwrap(), false);
        // A's key is untouched.
        assert!(storage.public_key(&SECRET_A, &key_id).is_ok());
    }

    #[test]
    fn delete_removes_key_and_is_idempotent() {
        let (storage, _dir) = tmp_storage();
        let (key_id, _) = storage.create_key(&SECRET_A, Algorithm::Ed25519).unwrap();

        assert_eq!(storage.delete_key(&SECRET_A, &key_id).unwrap(), true);
        assert_eq!(storage.list_keys(&SECRET_A).unwrap(), Vec::<String>::new());
        // Deleting again is a no-op, not an error.
        assert_eq!(storage.delete_key(&SECRET_A, &key_id).unwrap(), false);
    }

    #[test]
    fn list_keys_on_unused_namespace_is_empty_not_an_error() {
        let (storage, _dir) = tmp_storage();
        assert_eq!(storage.list_keys(&SECRET_A).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (storage, dir) = tmp_storage();
        let (key_id, _) = storage.create_key(&SECRET_A, Algorithm::Ed25519).unwrap();

        let path = dir.path().join(namespace_id(&SECRET_A).unwrap()).join(format!("{key_id}.key"));
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 0xFF;
        fs::write(&path, bytes).unwrap();

        assert!(matches!(storage.sign(&SECRET_A, &key_id, b"x").unwrap_err(), Error::Corrupt));
    }
}
