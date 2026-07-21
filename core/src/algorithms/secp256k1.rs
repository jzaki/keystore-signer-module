use k256::ecdsa::signature::{Signer as _, Verifier as _};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use super::Error;

pub struct Secp256k1Key(SigningKey);

impl Secp256k1Key {
    pub fn generate() -> Self {
        Self(SigningKey::random(&mut OsRng))
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let key = SigningKey::from_slice(bytes).map_err(|_| Error::InvalidKeyBytes)?;
        Ok(Self(key))
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        // SEC1 compressed point (33 bytes) — the conventional wire form.
        self.0.verifying_key().to_encoded_point(true).as_bytes().to_vec()
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig: Signature = self.0.sign(message);
        sig.to_bytes().to_vec()
    }

    pub fn secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_bytes().to_vec())
    }
}

pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, Error> {
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| Error::InvalidPublicKey)?;
    let sig = Signature::from_slice(signature).map_err(|_| Error::InvalidSignature)?;
    Ok(verifying_key.verify(message, &sig).is_ok())
}
