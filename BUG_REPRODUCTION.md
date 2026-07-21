# Cross-caller `bstr` argument corruption in generated Rust module dispatch

## Summary

A Logos Rust `cdylib` provider module with a method taking a `bstr` parameter
receives the **wrong argument value** — matching a *different* calling
module's most recent call — when a second calling module makes any call to
the same provider between two calls from the first calling module. The
provider-side code never sees the value its own caller actually sent; it sees
a stale value left over from whichever module called most recently.

This is not a bug in the reproduction module's own logic: the same secret
value is proven (by pointer and byte comparison, see below) to be stable and
correctly cached on the *calling* side across both calls. The corruption
happens strictly on the receiving/dispatch side, and strictly when a
different calling module's call intervenes.

## Environment

- `keystore_signer` module in this repo, built via `nix build` against the
  flake inputs pinned in `flake.lock` / `tests/flake.lock` (`logos-module-builder`,
  `logos-rust-sdk`, `logos-protocol`, `logos-logoscore-cli`, all `github:logos-co/*`,
  resolved 2026-07-21/22).
- `x86_64-linux`, Nix 2.34.6.
- Rust `cdylib` authoring path (`"interface": "cdylib"` + `codegen.lidl` +
  `codegen.rust` in `metadata.json`), i.e. `logos-lidl-gen`-generated
  `provider_gen.rs` + the generated Qt/cdylib glue, driven by `logoscore`.

## Minimal reproduction

This repo's `tests/` contains three modules built from one `.lidl`-driven
pipeline: `keystore_signer` (the provider) and two structurally identical
callers, `test_caller_a` and `test_caller_b`, each of which calls
`modules().keystore_signer.*(...)` using its own locally-generated 32-byte
secret.

```bash
cd tests
nix build .#checks.x86_64-linux.isolation-test -L
```

This drives a real `logoscore -D` daemon, loads all three modules, and issues
`logoscore call` invocations. Trimmed to the essential sequence (see
`tests/flake.nix` for the full script):

```sh
KEY_A=$(logoscore call test_caller_a createKey ed25519 | jq -r .result)
KEY_B=$(logoscore call test_caller_b createKey secp256k1 | jq -r .result)
logoscore call test_caller_a sign "$KEY_A" hello   # <- fails, see below
```

### Expected

`test_caller_a.sign` looks up `KEY_A` in the keystore namespace derived from
`test_caller_a`'s own secret (the same namespace its own `createKey` call
just wrote into) and returns a real signature.

### Actual

`test_caller_a.sign` looks up `KEY_A` in the namespace derived from
`test_caller_b`'s secret — the namespace `test_caller_b`'s `createKey` call
(which ran in between) wrote into — and gets `KeyNotFound`.

## Diagnostic evidence

Debug logging was added at three points: (1) the calling module
(`test_caller_a`), printing the secret it's about to send, its self pointer,
and whether it came from cache; (2) the provider (`keystore_signer`), printing
the secret it received; (3) the storage layer, printing the exact file path
being written/read. Full logs below (host/pid/timestamps trimmed for
readability; module tag preserved).

**Case 1 — A creates a key, then A signs immediately (no other caller
involved in between): succeeds.**

```
[test_caller_a] secret() was_cached=false self_ptr=0x5ecf30 first_bytes=[3f, af, 7a, 9, 68, 75, f, 50]
[keystore_signer] create_key secret.len=32 algorithm="ed25519"
[keystore_signer] with_keystore was_cached=false path=".../data/keystore_signer/c4b7f201a222"
[keystore_signer_core] seal writing to ".../c4b7f201a222/9c2ed6b6.../a618c3b6....key" (61 bytes)
[keystore_signer_core] seal wrote; exists_now=true
[keystore_signer] create_key -> Ok("a618c3b628909aa5fe06e5a9cf444b62")

[test_caller_a] secret() was_cached=true self_ptr=0x5ecf30 first_bytes=[3f, af, 7a, 9, 68, 75, f, 50]   # identical to above
[keystore_signer] sign secret_and_message.len=36 key_id="a618c3b628909aa5fe06e5a9cf444b62"
[keystore_signer] sign unpacked secret.len=32 message.len=0
[keystore_signer] with_keystore was_cached=true (reusing)
[keystore_signer_core] open reading from ".../9c2ed6b6.../a618c3b6....key" exists=true dir_exists=true
[keystore_signer] sign -> Ok(64)   # <- correct: same namespace (9c2ed6b6...) as create_key wrote
```

**Case 2 — A creates a key, B creates a (different) key, then A signs with
its own key id: fails.**

```
[test_caller_a] secret() was_cached=false self_ptr=0x5ecf30 first_bytes=[d6, f6, e2, 54, 30, f3, e7, 9b]
[keystore_signer] create_key secret.len=32 algorithm="ed25519"
[keystore_signer] with_keystore was_cached=false path=".../data/keystore_signer/e6130beffd08"
[keystore_signer_core] seal writing to ".../e6130beffd08/3b7d3b13.../c752bf11....key" (61 bytes)
[keystore_signer] create_key -> Ok("c752bf11ae8c99e91bf8d035bbe4999e")     # A's key, namespace 3b7d3b13...

[keystore_signer] create_key secret.len=32 algorithm="secp256k1"           # <- B's call, different process
[keystore_signer_core] seal writing to ".../e6130beffd08/3929dde2.../3753e8e1....key" (61 bytes)
[keystore_signer] create_key -> Ok("3753e8e109c26e7bf4a971505ca10dbc")     # B's key, namespace 3929dde2...

[test_caller_a] secret() was_cached=true self_ptr=0x5ecf30 first_bytes=[d6, f6, e2, 54, 30, f3, e7, 9b]  # still identical to A's own first call
[keystore_signer] sign secret.len=32 key_id="c752bf11ae8c99e91bf8d035bbe4999e"   # A's own key id, correct
[keystore_signer] with_keystore was_cached=true (reusing)
[keystore_signer_core] open reading from ".../3929dde2.../c752bf11....key" exists=false dir_exists=true
                                              ^^^^^^^^^^ B's namespace, not A's (3b7d3b13...)
[keystore_signer] sign -> Err(Storage(KeyNotFound))
```

`test_caller_a`'s own secret is proven identical across both its calls (same
pointer, same first 8 bytes). `key_id` in the failing `sign` call is
correctly `c752bf11...` (A's own key). But the namespace `sign` actually
looked in — `3929dde2...` — is exactly the namespace `test_caller_b`'s
*intervening* `createKey` call wrote to, not `test_caller_a`'s own
(`3b7d3b13...`). The `secret` argument `keystore_signer`'s `sign` handler
received must therefore not be the bytes `test_caller_a` sent.

## What was ruled out

Two structural changes were tried and **neither changed the outcome** —
Case 2 fails identically both ways:

1. **Argument order.** Reordered `sign`'s `.lidl` signature from
   `sign(secret: bstr, keyId: tstr, message: bstr)` to
   `sign(secret: bstr, message: bstr, keyId: tstr)` (grouping the two `bstr`
   params adjacently instead of separated by a `tstr`). Same failure, same
   namespace mismatch.
2. **Argument count/shape.** Packed `secret` and `message` into a single
   `bstr` (`[u32 LE secret_len][secret][message]`), reducing `sign` to
   `sign(secretAndMessage: bstr, keyId: tstr) -> bstr` — the exact same
   `(bstr, tstr)` shape as the *working* `createKey(secret: bstr, algorithm:
   tstr) -> tstr`. Still failed identically (see Case 2 log above, which is
   from this packed variant — `secret_and_message.len=36` = 4-byte prefix +
   32-byte secret + 0-byte message, unpacked correctly to `secret.len=32`,
   yet still resolved to B's namespace).

This rules out both "argument position" and "multiple `bstr` params in one
call" as the trigger. The pattern that *does* hold across every trial: the
corrupted value always matches whatever the **most recent call from a
different calling module** supplied for an argument in the same position/slot
shape — regardless of that other call's method name, argument count, or the
current call's own argument order.

## Suspected cause (unconfirmed)

Points at a stale-value bug in the generated provider-side dispatch for
`bstr` arguments — plausibly a buffer or slot that's reused across separate
inbound calls/connections keyed by position or type rather than freshly
populated per-dispatch, so a second calling module's call can leak a `bstr`
value into a later, unrelated call from a first calling module. Candidates
worth checking first: `logos-lidl-gen`'s generated `provider_gen.rs` dispatch
table's handling of `bstr` args (`logos_rust_sdk::bytes::decode`, see the
`"firmware" => ...` case in a generated `provider_gen.rs`), and the cdylib →
Qt glue layer each inbound call crosses before reaching that dispatch table.
Not independently confirmed — this repo's own code has no visibility into
either.

## Impact

Blocks any Rust `cdylib` provider method that takes a `bstr` argument and is
called by more than one distinct calling module in the same session — i.e.
exactly the shape a shared, multi-tenant service module (like a keystore)
needs for its core operation. `createKey`/`publicKey`/`listKeys`/`deleteKey`
in this module happen to work in the scenarios tested so far (single `bstr`
arg, or not yet tested under the same interleaving); `sign` is the one
confirmed broken because it's the one repeatedly exercised across this
diagnosis. It would be worth re-testing the others under the same
A-creates/B-creates/A-calls interleaving before assuming they're unaffected.
