//! Companion lib for a module that depends on `keystore_signer`.
//!
//! keystore_signer partitions all key material by a bearer secret the
//! *calling* module presents on every call — the Logos platform does not
//! (and structurally cannot, per its generic method-dispatch model) tell a
//! provider which module is calling it, so keystore_signer enforces
//! isolation itself, keyed on possession of that secret. This crate owns
//! the secret's lifecycle: generate it once, persist it in the calling
//! module's own (host-isolated) `instance_persistence_path`, and hand it
//! back on every later load. See [`Credential`].
//!
//! This crate also re-exports [`verify`] and the hashing helpers from
//! `keystore-signer-core` for **local, no-IPC** use: verifying a signature
//! or hashing a payload needs no private key material and no round trip to
//! the keystore_signer module.
//!
//! ## Calling keystore_signer itself
//!
//! This crate deliberately does **not** wrap the `sign`/`createKey`/etc. IPC
//! calls. Those are only reachable through the *typed* `modules().keystore_signer`
//! accessor Logos generates from `keystore_signer.lidl` — and that accessor
//! only exists inside a module's own generated glue (it's per-consumer
//! codegen, not something an ordinary library crate can obtain). So the
//! calling module's impl makes that one-line call itself, using the secret
//! this crate manages:
//!
//! ```ignore
//! let credential = keystore_signer_client::Credential::load_or_create(
//!     &context().unwrap().instance_persistence_path,
//! )?;
//! let key_id = modules().keystore_signer.create_key(
//!     &credential.secret_hex(), "ed25519",
//! );
//! let signature = modules().keystore_signer.sign(
//!     &credential.secret_hex(), &key_id, &message,
//! );
//! assert!(keystore_signer_client::verify(
//!     keystore_signer_client::Algorithm::Ed25519, &public_key, &message, &signature,
//! )?);
//! ```

use std::fs;
use std::io;
use std::path::Path;

use rand::rngs::OsRng;
use rand::RngCore as _;
use zeroize::Zeroizing;

pub use keystore_signer_core::{keccak256, sha256, verify, Algorithm};

/// File name the credential is persisted under, inside the calling module's
/// `instance_persistence_path`.
const CREDENTIAL_FILE_NAME: &str = "keystore_signer_credential";

/// Bearer secrets are 256 bits — see `keystore_signer_core::registry::MIN_SECRET_LEN`.
const SECRET_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("instance_persistence_path is empty — the host hasn't provisioned one (see LogosModuleContext docs); a real path is required to persist the credential")]
    NoPersistencePath,
    #[error("stored credential at {path} is {len} bytes, expected {SECRET_LEN}")]
    CorruptCredential { path: String, len: usize },
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// The calling module's bearer secret for keystore_signer, loaded from (or
/// generated into) its private persistence directory. Holding one of these
/// is exactly equivalent to owning that module's keystore_signer namespace —
/// treat it like a private key.
pub struct Credential(Zeroizing<[u8; SECRET_LEN]>);

impl Credential {
    /// Load the persisted secret from `instance_persistence_path`, or
    /// generate and persist a new one on first use.
    ///
    /// Concurrency: this assumes the default Logos dispatch model, where
    /// module setup (`onContextReady`) runs once, serialized — it does not
    /// attempt to be race-free against concurrent first-use from multiple
    /// threads.
    pub fn load_or_create(instance_persistence_path: &str) -> Result<Self, Error> {
        if instance_persistence_path.is_empty() {
            return Err(Error::NoPersistencePath);
        }
        let dir = Path::new(instance_persistence_path);
        fs::create_dir_all(dir)?;
        let path = dir.join(CREDENTIAL_FILE_NAME);

        match fs::read(&path) {
            Ok(bytes) => {
                let secret: [u8; SECRET_LEN] = bytes.try_into().map_err(|bytes: Vec<u8>| {
                    Error::CorruptCredential { path: path.display().to_string(), len: bytes.len() }
                })?;
                Ok(Self(Zeroizing::new(secret)))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Self::generate_and_persist(&path),
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn generate_and_persist(path: &Path) -> Result<Self, Error> {
        let mut secret = [0u8; SECRET_LEN];
        OsRng.fill_bytes(&mut secret);
        fs::write(path, secret)?;
        restrict_permissions(path)?;
        Ok(Self(Zeroizing::new(secret)))
    }

    pub fn secret_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Hex-encoded secret, ready to pass as keystore_signer's `secret: tstr`
    /// argument. keystore_signer's `.lidl` contract takes `secret` as `tstr`
    /// (not `bstr`) specifically so callers go through this — see
    /// BUG_REPRODUCTION.md for why.
    pub fn secret_hex(&self) -> String {
        hex::encode(&self.0[..])
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_path_is_rejected() {
        assert!(matches!(Credential::load_or_create(""), Err(Error::NoPersistencePath)));
    }

    #[test]
    fn generates_and_persists_then_reloads_the_same_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();

        let first = Credential::load_or_create(path).unwrap();
        let second = Credential::load_or_create(path).unwrap();
        assert_eq!(first.secret_bytes(), second.secret_bytes());
    }

    #[test]
    fn different_directories_get_different_secrets() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();

        let a = Credential::load_or_create(dir_a.path().to_str().unwrap()).unwrap();
        let b = Credential::load_or_create(dir_b.path().to_str().unwrap()).unwrap();
        assert_ne!(a.secret_bytes(), b.secret_bytes());
    }

    #[test]
    fn credential_file_has_owner_only_permissions_on_unix() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let dir = tempfile::tempdir().unwrap();
            Credential::load_or_create(dir.path().to_str().unwrap()).unwrap();
            let meta = fs::metadata(dir.path().join(CREDENTIAL_FILE_NAME)).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn corrupt_credential_file_is_rejected() {
        // Not `.unwrap_err()`: Credential deliberately doesn't derive Debug
        // (it wraps secret material) so match the Result directly instead.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(CREDENTIAL_FILE_NAME), b"too short").unwrap();
        match Credential::load_or_create(dir.path().to_str().unwrap()) {
            Err(Error::CorruptCredential { .. }) => {}
            _ => panic!("expected CorruptCredential"),
        }
    }

    #[test]
    fn secret_hex_round_trips_to_secret_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let cred = Credential::load_or_create(dir.path().to_str().unwrap()).unwrap();
        let hex_str = cred.secret_hex();
        assert_eq!(hex_str.len(), SECRET_LEN * 2);
        assert_eq!(hex::decode(&hex_str).unwrap(), cred.secret_bytes());
    }

    #[test]
    fn local_verify_matches_core_round_trip() {
        // Sanity check that the re-exported verify/Algorithm work as a
        // consuming module would use them, without touching keystore_signer.
        let key = keystore_signer_core::KeyMaterial::generate(Algorithm::Ed25519);
        let msg = b"local verification needs no IPC";
        let sig = key.sign(msg);
        assert!(verify(Algorithm::Ed25519, &key.public_key_bytes(), msg, &sig).unwrap());
    }
}
