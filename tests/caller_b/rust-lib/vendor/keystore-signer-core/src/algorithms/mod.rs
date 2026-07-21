mod bls;
mod ed25519;
mod secp256k1;

use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("unknown algorithm: {0}")]
    UnknownAlgorithm(String),
    #[error("invalid key bytes for this algorithm")]
    InvalidKeyBytes,
    #[error("invalid signature bytes")]
    InvalidSignature,
    #[error("invalid public key bytes")]
    InvalidPublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Ed25519,
    Secp256k1,
    Bls12_381,
}

impl Algorithm {
    pub fn parse(name: &str) -> Result<Self, Error> {
        match name {
            "ed25519" => Ok(Algorithm::Ed25519),
            "secp256k1" => Ok(Algorithm::Secp256k1),
            "bls12_381" => Ok(Algorithm::Bls12_381),
            other => Err(Error::UnknownAlgorithm(other.to_string())),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::Ed25519 => "ed25519",
            Algorithm::Secp256k1 => "secp256k1",
            Algorithm::Bls12_381 => "bls12_381",
        }
    }
}

/// A generated or restored keypair. The private component never leaves this
/// type except through `secret_bytes()`, which callers must seal (encrypt)
/// or zeroize immediately — see `storage.rs`.
pub enum KeyMaterial {
    Ed25519(ed25519::Ed25519Key),
    Secp256k1(secp256k1::Secp256k1Key),
    Bls12_381(bls::BlsKey),
}

impl KeyMaterial {
    pub fn generate(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Ed25519 => KeyMaterial::Ed25519(ed25519::Ed25519Key::generate()),
            Algorithm::Secp256k1 => KeyMaterial::Secp256k1(secp256k1::Secp256k1Key::generate()),
            Algorithm::Bls12_381 => KeyMaterial::Bls12_381(bls::BlsKey::generate()),
        }
    }

    pub fn algorithm(&self) -> Algorithm {
        match self {
            KeyMaterial::Ed25519(_) => Algorithm::Ed25519,
            KeyMaterial::Secp256k1(_) => Algorithm::Secp256k1,
            KeyMaterial::Bls12_381(_) => Algorithm::Bls12_381,
        }
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            KeyMaterial::Ed25519(k) => k.public_key_bytes(),
            KeyMaterial::Secp256k1(k) => k.public_key_bytes(),
            KeyMaterial::Bls12_381(k) => k.public_key_bytes(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            KeyMaterial::Ed25519(k) => k.sign(message),
            KeyMaterial::Secp256k1(k) => k.sign(message),
            KeyMaterial::Bls12_381(k) => k.sign(message),
        }
    }

    /// Raw secret scalar/seed bytes, for encrypted-at-rest persistence only.
    pub fn secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        match self {
            KeyMaterial::Ed25519(k) => k.secret_bytes(),
            KeyMaterial::Secp256k1(k) => k.secret_bytes(),
            KeyMaterial::Bls12_381(k) => k.secret_bytes(),
        }
    }

    pub fn from_secret_bytes(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, Error> {
        Ok(match algorithm {
            Algorithm::Ed25519 => KeyMaterial::Ed25519(ed25519::Ed25519Key::from_secret_bytes(bytes)?),
            Algorithm::Secp256k1 => {
                KeyMaterial::Secp256k1(secp256k1::Secp256k1Key::from_secret_bytes(bytes)?)
            }
            Algorithm::Bls12_381 => KeyMaterial::Bls12_381(bls::BlsKey::from_secret_bytes(bytes)?),
        })
    }
}

/// Verify a signature against a public key. Pure function — no key storage
/// involved, safe to call from the module or, more usefully, entirely
/// client-side (see keystore-signer-client).
pub fn verify(
    algorithm: Algorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, Error> {
    match algorithm {
        Algorithm::Ed25519 => ed25519::verify(public_key, message, signature),
        Algorithm::Secp256k1 => secp256k1::verify(public_key, message, signature),
        Algorithm::Bls12_381 => bls::verify(public_key, message, signature),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_round_trips_through_str() {
        for algo in [Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::Bls12_381] {
            assert_eq!(Algorithm::parse(algo.as_str()).unwrap(), algo);
        }
    }

    #[test]
    fn unknown_algorithm_is_rejected() {
        assert_eq!(
            Algorithm::parse("rot13"),
            Err(Error::UnknownAlgorithm("rot13".to_string()))
        );
    }

    #[test]
    fn each_algorithm_signs_and_verifies() {
        for algo in [Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::Bls12_381] {
            let key = KeyMaterial::generate(algo);
            let msg = b"hello keystore_signer";
            let sig = key.sign(msg);
            let pk = key.public_key_bytes();
            assert!(verify(algo, &pk, msg, &sig).unwrap(), "{algo:?} verify failed");
            assert!(
                !verify(algo, &pk, b"tampered", &sig).unwrap(),
                "{algo:?} accepted a tampered message"
            );
        }
    }

    #[test]
    fn each_algorithm_round_trips_secret_bytes() {
        for algo in [Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::Bls12_381] {
            let key = KeyMaterial::generate(algo);
            let secret = key.secret_bytes();
            let restored = KeyMaterial::from_secret_bytes(algo, &secret).unwrap();
            assert_eq!(restored.public_key_bytes(), key.public_key_bytes());
        }
    }

    #[test]
    fn cross_algorithm_public_key_is_rejected_not_misinterpreted() {
        // A secp256k1 public key handed to ed25519 verify() must not verify —
        // it must either fail to parse or fail verification, never succeed.
        let secp = KeyMaterial::generate(Algorithm::Secp256k1);
        let msg = b"hi";
        let sig = secp.sign(msg);
        let result = verify(Algorithm::Ed25519, &secp.public_key_bytes(), msg, &sig);
        assert!(matches!(result, Err(_)) || result == Ok(false));
    }
}
