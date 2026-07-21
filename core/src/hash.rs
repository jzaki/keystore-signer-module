//! Stateless hashing helpers. No key material involved — safe to run
//! entirely client-side (the companion lib re-exports these directly).

// sha2 and sha3 both re-export the same underlying `digest::Digest` trait,
// so importing it once covers both `Sha256::digest` and `Keccak256::digest`.
use sha2::Digest as _;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

/// Ethereum-style Keccak-256 (the original Keccak padding, not NIST SHA3-256).
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    sha3::Keccak256::digest(data).into()
}
