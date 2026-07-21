//! Caller namespacing.
//!
//! keystore_signer has no separate "list of registered callers" to consult.
//! A caller's namespace id is *derived* from its bearer secret
//! (`sha256(secret)`), and that same secret feeds the HKDF that derives the
//! namespace's storage encryption key (see `storage.rs`). So there is
//! nothing to look up and nothing to compare: presenting the wrong secret
//! computes a different namespace id and a different storage key, which at
//! worst finds someone else's directory (and fails to decrypt anything in
//! it) or, far more likely, an empty/nonexistent namespace. Isolation falls
//! out of the derivation being one-way and per-secret, not from an access
//! check anyone could get wrong.

use thiserror::Error;

use crate::hash::sha256;

/// Bearer secrets are 256-bit bearer capabilities, not passwords — this is a
/// floor against a caller (or a bug in a caller) using something degenerate
/// like an empty string as its only proof of identity.
pub const MIN_SECRET_LEN: usize = 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("secret must be at least {MIN_SECRET_LEN} bytes, got {0}")]
    SecretTooShort(usize),
}

/// Deterministically derive a caller's private namespace id from its secret.
pub fn namespace_id(secret: &[u8]) -> Result<String, Error> {
    if secret.len() < MIN_SECRET_LEN {
        return Err(Error::SecretTooShort(secret.len()));
    }
    Ok(hex::encode(sha256(secret)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_secret_yields_same_namespace() {
        let secret = [7u8; 32];
        assert_eq!(namespace_id(&secret), namespace_id(&secret));
    }

    #[test]
    fn different_secrets_yield_different_namespaces() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(namespace_id(&a).unwrap(), namespace_id(&b).unwrap());
    }

    #[test]
    fn short_secret_is_rejected() {
        assert_eq!(namespace_id(&[0u8; 16]), Err(Error::SecretTooShort(16)));
    }
}
