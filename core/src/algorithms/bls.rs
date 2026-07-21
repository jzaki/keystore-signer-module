use blst::min_pk::{PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use rand::rngs::OsRng;
use rand::RngCore as _;
use zeroize::{Zeroize as _, Zeroizing};

use super::Error;

/// Standard IETF domain-separation tag for the "basic" (non-aggregating,
/// non-augmented) BLS signature scheme over BLS12-381 G2, matching the
/// ciphersuite blst's min_pk module implements.
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

pub struct BlsKey(SecretKey);

impl BlsKey {
    pub fn generate() -> Self {
        // blst's key_gen wants >= 32 bytes of key material (IKM); 32 random
        // bytes from an OS CSPRNG satisfy that with no manual biasing.
        let mut ikm = [0u8; 32];
        OsRng.fill_bytes(&mut ikm);
        let sk = SecretKey::key_gen(&ikm, &[]).expect("32-byte IKM satisfies blst's minimum");
        ikm.zeroize();
        Self(sk)
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, Error> {
        SecretKey::from_bytes(bytes).map(Self).map_err(|_| Error::InvalidKeyBytes)
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.0.sk_to_pk().to_bytes().to_vec()
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.0.sign(message, DST, &[]).to_bytes().to_vec()
    }

    pub fn secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_bytes().to_vec())
    }
}

pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, Error> {
    let pk = PublicKey::from_bytes(public_key).map_err(|_| Error::InvalidPublicKey)?;
    let sig = Signature::from_bytes(signature).map_err(|_| Error::InvalidSignature)?;
    let result = sig.verify(true, message, DST, &[], &pk, true);
    Ok(result == BLST_ERROR::BLST_SUCCESS)
}
