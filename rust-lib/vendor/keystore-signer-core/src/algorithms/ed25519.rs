use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use super::Error;

pub struct Ed25519Key(SigningKey);

impl Ed25519Key {
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let seed: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidKeyBytes)?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.0.sign(message).to_bytes().to_vec()
    }

    pub fn secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_bytes().to_vec())
    }
}

pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, Error> {
    let pk_bytes: [u8; 32] = public_key.try_into().map_err(|_| Error::InvalidPublicKey)?;
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| Error::InvalidPublicKey)?;
    let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| Error::InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);
    Ok(verifying_key.verify(message, &sig).is_ok())
}
