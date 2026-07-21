//! Pure-Rust logic for keystore_signer: per-caller isolated key storage,
//! signing (Ed25519 / secp256k1 / BLS12-381), and hashing.
//!
//! This crate has no dependency on Logos/IPC machinery — it's usable
//! standalone (and `cargo test`-able without the module build pipeline).
//! `rust-lib/` wraps `Keystore` in the generated Logos provider trait;
//! `keystore-signer-client` links this same crate for local verification
//! and hashing, so both sides of the module boundary share one
//! implementation of the math.

pub mod algorithms;
pub mod hash;
pub mod registry;
pub mod storage;

pub use algorithms::{verify, Algorithm, KeyMaterial};
pub use hash::{keccak256, sha256};

use std::path::PathBuf;

use storage::Storage;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Namespace(#[from] registry::Error),
    #[error(transparent)]
    Storage(#[from] storage::Error),
    #[error(transparent)]
    Algorithm(#[from] algorithms::Error),
}

/// The server-side facade: everything keystore_signer's provider trait impl
/// needs, keyed on the caller's bearer secret. One instance per module
/// process, shared (as a singleton) by every calling module.
pub struct Keystore {
    storage: Storage,
}

impl Keystore {
    pub fn new(persistence_root: impl Into<PathBuf>) -> Self {
        Self { storage: Storage::new(persistence_root) }
    }

    pub fn create_key(&self, secret: &[u8], algorithm: &str) -> Result<String, Error> {
        let algorithm = Algorithm::parse(algorithm)?;
        let (key_id, _public_key) = self.storage.create_key(secret, algorithm)?;
        Ok(key_id)
    }

    pub fn public_key(&self, secret: &[u8], key_id: &str) -> Result<Vec<u8>, Error> {
        Ok(self.storage.public_key(secret, key_id)?)
    }

    pub fn sign(&self, secret: &[u8], key_id: &str, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.storage.sign(secret, key_id, message)?)
    }

    pub fn list_keys(&self, secret: &[u8]) -> Result<Vec<String>, Error> {
        Ok(self.storage.list_keys(secret)?)
    }

    pub fn delete_key(&self, secret: &[u8], key_id: &str) -> Result<bool, Error> {
        Ok(self.storage.delete_key(secret, key_id)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end_create_sign_verify() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let secret = [9u8; 32];

        let key_id = ks.create_key(&secret, "ed25519").unwrap();
        let pk = ks.public_key(&secret, &key_id).unwrap();
        let sig = ks.sign(&secret, &key_id, b"msg").unwrap();

        assert!(verify(Algorithm::Ed25519, &pk, b"msg", &sig).unwrap());
    }

    #[test]
    fn unknown_algorithm_name_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        assert!(ks.create_key(&[9u8; 32], "rsa4096").is_err());
    }
}
