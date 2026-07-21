//! test_caller_a — integration test fixture. Thin pass-through to
//! keystore_signer using this module's own credential (managed by
//! keystore-signer-client), so an external test driver (see
//! `tests/flake.nix`'s `isolation-test` check) can prove that test_caller_b
//! cannot read or sign with this module's keys, and vice versa, over real
//! Logos IPC.

use keystore_signer_client::Credential;
use serde_json::Value;

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct CallerImpl {
    credential: Option<Credential>,
}

impl CallerImpl {
    fn secret(&mut self) -> Vec<u8> {
        if self.credential.is_none() {
            let path = context()
                .map(|c| c.instance_persistence_path)
                .filter(|p| !p.is_empty())
                .expect("test_caller_a requires a host-provisioned instance_persistence_path");
            self.credential =
                Some(Credential::load_or_create(&path).expect("failed to load/create credential"));
        }
        self.credential.as_ref().unwrap().secret_bytes().to_vec()
    }
}

// The generated modules().keystore_signer client takes borrowed args
// (&[u8]/&str) and returns Result<_, LogosError> — confirmed from a real
// generated provider_gen.rs (2026-07-21 nix build). Same "empty means
// failure" convention as keystore_signer's own provider side: unwrap_or_*
// rather than propagating LogosError, since there's no `result` envelope
// declared in this module's own .lidl contract either.
impl TestCallerAModule for CallerImpl {
    fn create_key(&mut self, algorithm: String) -> String {
        let secret = self.secret();
        modules().keystore_signer.create_key(&secret, &algorithm).unwrap_or_default()
    }

    fn public_key(&mut self, key_id: String) -> Vec<u8> {
        let secret = self.secret();
        modules().keystore_signer.public_key(&secret, &key_id).unwrap_or_default()
    }

    fn sign(&mut self, key_id: String, message: Vec<u8>) -> Vec<u8> {
        let secret = self.secret();
        modules().keystore_signer.sign(&secret, &key_id, &message).unwrap_or_default()
    }

    fn list_keys(&mut self) -> Value {
        let secret = self.secret();
        modules().keystore_signer.list_keys(&secret).unwrap_or(Value::Array(Vec::new()))
    }

    fn delete_key(&mut self, key_id: String) -> bool {
        let secret = self.secret();
        modules().keystore_signer.delete_key(&secret, &key_id).unwrap_or(false)
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<CallerImpl>();
}
