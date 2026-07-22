//! keystore_signer Logos module — thin glue delegating to `keystore_signer_core::Keystore`.
//!
//! The trait `KeystoreSignerModule`, the `context()` accessor, and
//! `install::<T>()` below come from `generated/provider_gen.rs`, produced at build time by
//! logos-lidl-gen from `keystore_signer.lidl` (see `../metadata.json`'s
//! `codegen` block) — this file is not meant to `cargo build` standalone
//! outside the Logos module Nix pipeline. The actual key storage, signing,
//! and per-caller isolation logic lives in the sibling `keystore-signer-core`
//! crate, which *is* standalone `cargo test`-able (`cargo test -p
//! keystore-signer-core` from the repo root).
//!
//! Failure signaling: methods return their "empty" value (`""`, `[]`,
//! `false`) on failure rather than a `result` envelope. Every real success
//! value is non-empty (key ids are 32 hex chars; public keys and signatures
//! are always a fixed non-zero length per algorithm), so this isn't lossy in
//! practice — and the one error that's actually reachable at runtime
//! (`keystore-signer-client` always presents a well-formed 32-byte secret)
//! is a caller bug, not a condition callers need to branch on.

use keystore_signer_core::Keystore;
use serde_json::Value;

// Brings `Mutex` (among others) into scope already — see the note on
// `Mutex<Option<Keystore>>` below.
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct KeystoreSignerImpl {
    keystore: Mutex<Option<Keystore>>,
}

impl KeystoreSignerImpl {
    /// The keystore can't be built until the host stamps this instance's
    /// `instance_persistence_path` (available through `context()`), so it's
    /// constructed lazily on first dispatch rather than in `Default::default()`.
    fn with_keystore<R>(&self, f: impl FnOnce(&Keystore) -> R) -> R {
        let mut guard = self.keystore.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            let path = context()
                .map(|c| c.instance_persistence_path)
                .filter(|p| !p.is_empty())
                .expect("keystore_signer requires a host-provisioned instance_persistence_path");
            *guard = Some(Keystore::new(path));
        }
        f(guard.as_ref().unwrap())
    }
}

/// `secret` travels the wire as `tstr` (hex), not `bstr` — see
/// BUG_REPRODUCTION.md: a `bstr` in this argument slot was observed to
/// resolve to a *different calling module's* most recent value once a
/// second caller had made any call in between. Decoding here is the one
/// point that turns the hex string back into the raw bytes the storage
/// layer's namespace derivation expects. A malformed hex string decodes to
/// an empty Vec, which fails downstream (below the 32-byte minimum) the
/// same way any other bad secret does — no separate error path needed.
fn decode_secret(secret: &str) -> Vec<u8> {
    hex::decode(secret).unwrap_or_default()
}

impl KeystoreSignerModule for KeystoreSignerImpl {
    fn create_key(&mut self, secret: String, algorithm: String) -> String {
        let secret = decode_secret(&secret);
        self.with_keystore(|ks| ks.create_key(&secret, &algorithm).unwrap_or_default())
    }

    fn public_key(&mut self, secret: String, key_id: String) -> Vec<u8> {
        let secret = decode_secret(&secret);
        self.with_keystore(|ks| ks.public_key(&secret, &key_id).unwrap_or_default())
    }

    fn sign(&mut self, secret: String, key_id: String, message: Vec<u8>) -> Vec<u8> {
        let secret = decode_secret(&secret);
        self.with_keystore(|ks| ks.sign(&secret, &key_id, &message).unwrap_or_default())
    }

    fn list_keys(&mut self, secret: String) -> Value {
        let secret = decode_secret(&secret);
        let ids = self.with_keystore(|ks| ks.list_keys(&secret).unwrap_or_default());
        Value::Array(ids.into_iter().map(Value::String).collect())
    }

    fn delete_key(&mut self, secret: String, key_id: String) -> bool {
        let secret = decode_secret(&secret);
        self.with_keystore(|ks| ks.delete_key(&secret, &key_id).unwrap_or(false))
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<KeystoreSignerImpl>();
}
