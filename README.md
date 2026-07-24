# keystore_signer

A Logos module that gives other modules an isolated place to generate keys and
sign with them, without ever exposing private key material — to the calling
module, or to any other module that also depends on `keystore_signer`.

Supports Ed25519, secp256k1 (ECDSA), and BLS12-381 signing, plus keccak256/
sha256 hashing (the hashing and signature-verification helpers run entirely
client-side, no IPC required).

> **Formerly broken, now fixed upstream:** cross-module calls into `sign`
> used to receive a *different calling module's* most recent argument value
> once a second caller had made any call in between — a platform-level bug,
> not this module's. Fixed as of `logos-logoscore-cli` 0.2.2-RC1 (pinned in
> `tests/flake.nix`); see [BUG_REPRODUCTION.md](BUG_REPRODUCTION.md) for the
> full diagnostic history.

## Why this exists

Logos modules are loaded as **singletons** — one instance shared by every
module that depends on it. The platform's inter-module call dispatch
authenticates "is this caller legitimate" but does not tell a module *which*
module is calling it (confirmed by reading the SDK's own auth-token
regression tests: a token proves membership, not identity). So a naively
shared keystore has no way to stop module B from listing or signing with
module A's keys — there's nothing in the platform to gate on.

`keystore_signer` closes that gap itself: every method takes a `secret`
bearer credential, and a caller's whole keyspace is derived from it
(`sha256(secret)` as the namespace id; the same secret HKDF-derives the
at-rest encryption key for that namespace). There's no separate "list of
registered callers" to get out of sync — knowing the secret *is* having
access, and not knowing it makes another caller's namespace both
undiscoverable and, if you somehow found the right directory, undecryptable.
See `core/src/registry.rs` and `core/src/storage.rs` for the full reasoning.

The [`keystore-signer-client`](keystore-signer-client) companion crate is
what makes this invisible to a normal module author: it generates a random
256-bit secret the first time a module uses it, persists it in that module's
own (host-isolated) `instance_persistence_path`, and hands it back on every
later load. A module author never sees or manages the secret directly.

## Repo layout

```
metadata.json, flake.nix, CMakeLists.txt   keystore_signer module definition
rust-lib/                                  the module itself (Rust, cdylib)
  keystore_signer.lidl                       the wire contract
  src/lib.rs                                 thin glue: Logos trait impl -> Keystore
  vendor/keystore-signer-core/                vendored copy of core/ (see below)

core/                                      pure-Rust logic, no Logos/IPC dependency
  src/algorithms/{ed25519,secp256k1,bls}.rs   sign/verify per algorithm
  src/registry.rs                             secret -> namespace derivation
  src/storage.rs                              encrypted-at-rest, per-namespace
  src/hash.rs                                 keccak256 / sha256

keystore-signer-client/                    companion lib for dependent modules
  src/lib.rs                                 credential bootstrap + local verify/hash

tests/                                     integration test fixtures + harness
  caller_a/, caller_b/                       two modules that each depend on
                                              keystore_signer via their own secret
  flake.nix                                  builds all three + a logoscore-driven
                                              isolation-test check
```

### Why `core` is vendored into `rust-lib/vendor/` (and into each test caller)

The Logos Rust build stages a module's `codegen.rust.crate` directory (here,
`rust-lib/`) **in isolation** — confirmed empirically, not documented: `nix
build` fails to resolve `path = "../core"` because the sandboxed build root is
`.../rust-lib`, and sibling directories from the rest of the repo simply
aren't there. `keystore-signer-core` has no dependency on Logos/IPC machinery
and needs to be reachable from both the module (signing) and the client
(local verification), so — until it's published somewhere Cargo can fetch it
from independently (crates.io, or this repo's own eventual git remote) —
it's vendored: physically copied into `rust-lib/vendor/keystore-signer-core/`
and into each of `tests/caller_a/rust-lib/vendor/` and
`tests/caller_b/rust-lib/vendor/` (which also need a copy of
`keystore-signer-client`, for the same reason). `core/` at the repo root
remains the single canonical, tested copy — the vendored copies must be kept
in sync with it by hand (a plain `cp -r` diffed with `diff -r` before
committing) until that dependency can be expressed as a normal git/version
dependency instead.

## Building and testing

The pure-Rust logic — the part with real security-relevant behavior — builds
and tests without Nix or the Logos toolchain at all:

```bash
cargo test --workspace   # core (17 tests) + keystore-signer-client (6 tests)
```

Building the actual Logos module requires the Nix pipeline (fetches the full
`logos-module-builder`/`logos-protocol`/Qt toolchain — the first build takes
a while):

```bash
git add -A               # Nix only sees git-tracked files
nix build .#lib -L       # -> result/lib/keystore_signer_plugin.so
```

The integration test suite (`tests/`) builds `keystore_signer` plus two
caller fixtures and drives them through a real `logoscore` daemon:

```bash
cd tests
nix build .#checks.x86_64-linux.isolation-test -L
```

This passes end to end (see [BUG_REPRODUCTION.md](BUG_REPRODUCTION.md) for
the platform bug it used to catch, now fixed upstream).

## API (`rust-lib/keystore_signer.lidl`)

| Method | Signature | Notes |
|---|---|---|
| `createKey` | `(secret: bstr, algorithm: tstr) -> tstr` | `algorithm` is `"ed25519"` \| `"secp256k1"` \| `"bls12_381"`. Returns a key id, empty string on failure. |
| `publicKey` | `(secret: bstr, keyId: tstr) -> bstr` | Empty on failure (unknown key, or someone else's key id). |
| `sign` | `(secret: bstr, keyId: tstr, message: bstr) -> bstr` | Empty on failure. |
| `listKeys` | `(secret: bstr) -> [tstr]` | Key ids in the caller's own namespace only. |
| `deleteKey` | `(secret: bstr, keyId: tstr) -> bool` | `false` if the key id doesn't exist in the caller's namespace. |

There's no `result`/error-detail envelope: every real success value is
non-empty by construction (key ids are 32 hex chars; public keys and
signatures are a fixed non-zero length per algorithm), so "empty" is an
unambiguous failure signal. Private key material never leaves the module
through any method — there is no `exportKey`.

## Using it from another module

A dependent module declares `keystore_signer` in its own `metadata.json`
`dependencies` and links `keystore-signer-client`. The generated
`modules().keystore_signer` accessor only exists inside that module's own
generated glue, so the actual IPC call is a couple of lines in the module's
own code — `keystore-signer-client` handles the part worth centralizing (the
credential) and the fully local part (verification):

```rust
use keystore_signer_client::{Algorithm, Credential};

let credential = Credential::load_or_create(&context().unwrap().instance_persistence_path)?;
let secret = credential.secret_bytes();

let key_id = modules().keystore_signer
    .create_key(secret, "ed25519")?;
let public_key = modules().keystore_signer
    .public_key(secret, &key_id)?;
let signature = modules().keystore_signer
    .sign(secret, &key_id, &message)?;

// No IPC — pure local verification against the public key:
assert!(keystore_signer_client::verify(Algorithm::Ed25519, &public_key, &message, &signature)?);
```

See `tests/caller_a/rust-lib/src/lib.rs` for a complete worked example.

## Crypto stack

Chosen to match existing conventions in this ecosystem where they exist
(`logos-blockchain`, `logos-execution-zone`), and to fill in the rest
sensibly:

- Ed25519 — `ed25519-dalek` (same as `logos-blockchain`)
- secp256k1/ECDSA — `k256`, same feature set as `logos-blockchain`/
  `logos-execution-zone` (`ecdsa-core`, `arithmetic`, `expose-field`)
- BLS12-381 — `blst` (new to this ecosystem; the de facto standard,
  used by Ethereum consensus clients)
- keccak256 — `sha3::Keccak256` (same algorithm as `logos-execution-zone`'s
  `tiny-keccak`, different crate — chosen to share the RustCrypto `Digest`
  trait with `sha2`)
- `zeroize` for scrubbing secrets from memory, `chacha20poly1305` + `hkdf`
  for at-rest encryption — both already ecosystem conventions
