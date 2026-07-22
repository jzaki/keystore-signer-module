---
name: choose-module-architecture
description: Understand the tradeoffs between Rust cdylib and C++ universal module architectures — particularly caller context visibility, which affects multi-caller isolation and bug detection. Use when deciding which template to start with or debugging issues in existing modules.
---

# Choosing a Logos Module Architecture

When creating a Logos module, you have two primary paths via `nix flake init -t github:logos-co/logos-module-builder`:
- **`#default` (Rust cdylib)** — Write Rust, code-generated dispatch via LIDL
- **`#with-external-lib` (C++ universal)** — Write C++, wrap external C/C++ libraries

This skill explains the architectural tradeoffs, particularly around **caller context visibility**, which has direct implications for debugging and isolation bugs.

## Quick Decision Matrix

| Need | Rust cdylib | C++ with-external-lib |
|------|------------|----------------------|
| Wrap existing C/C++ library | ❌ Poor | ✅ Designed for this |
| Memory-safe crypto ops | ✅ Yes (via crates) | ⚠️ Manual `unsafe` blocks |
| Type-safe interface codegen | ✅ LIDL + Rust traits | ❌ Manual Qt glue |
| Access to module context in dispatch | ⚠️ Limited (C-ABI boundary) | ✅ Direct via LogosModuleContext |
| Multi-caller isolation | ⚠️ Caller identity lost at boundary | ⚠️ Same limitation applies |
| Fast dev iteration | ✅ Cargo ecosystem | ❌ CMake + C++ toolchain |

## The Context Visibility Problem

### Rust cdylib (current keystore-signer)

```
Caller A                Caller B
   │                       │
   └─── lp_client_create ──┴─→ keystore_signer's QtRO registry
          (caller ID known)
             │
             └─→ logos_module_dispatch(method, args_json)  ← C-ABI boundary
                    └─→ Rust handler receives ONLY:
                        - method name
                        - JSON-serialized args
                        - NO caller identity
                        - NO call context
```

**Result:** If QtRO's dynamic dispatch corrupts arguments (mixing one caller's `bstr` with another's), the Rust handler has **no way to detect it** — it can't correlate the received secret against the caller that sent it.

### C++ universal (template approach)

```
Caller A                Caller B
   │                       │
   └─── lp_client_create ──┴─→ ExternalLibImpl's LogosModuleContext
          (caller ID known)
             │
             └─→ ExternalLibImpl::methodName()
                    └─→ C++ handler has access to:
                        - LogosModuleContext (module context)
                        - Potentially: call identity, request context
                        - Can validate args against caller
```

**Potential advantage:** The C++ implementation class is still in-process in the module's `logos_host`, with direct access to `LogosModuleContext`. It *could* validate received arguments against expected caller identity, if that context were exposed.

**Reality check:** The template doesn't currently expose caller identity either. **Both architectures have the same limitation.** The difference is that C++ is *closer* to where that information exists — you could add validation plumbing without crossing a C-ABI boundary.

## When to Use Each

### Use Rust cdylib when:

- You're writing pure Logos logic in Rust
- Your dependencies are Rust crates (crypto, serialization, etc.)
- You need type-safe interface definitions (LIDL codegen)
- You want fast iteration with Cargo's ecosystem
- **Example:** keystore_signer (cryptographic operations, isolated namespace management)

### Use C++ with-external-lib when:

- You're wrapping a pre-built or vendored C/C++ library
- That library has no Rust bindings or you can't depend on it
- You need direct access to its C ABI without FFI overhead
- The library is memory-managed and you can contain the `unsafe` blocks
- **Example:** Wrapping libsodium, a legacy DSP library, platform-specific APIs

## The Caller Isolation Gap

**Both approaches suffer from the same fundamental issue:** the Logos platform's generic method-dispatch model doesn't propagate caller identity to the provider's handler.

### Current workaround in Rust:

keystore-signer enforces isolation by requiring the *caller* to present a bearer secret on every call:

```rust
// Caller's side (in test_caller_a)
let credential = Credential::load_or_create(&context().instance_persistence_path)?;
modules().keystore_signer.sign(
    credential.secret_bytes().to_vec(),  // Bearer secret = caller identity proof
    key_id,
    message
);

// Provider's side (in keystore_signer)
fn sign(&mut self, secret: Vec<u8>, key_id: String, message: Vec<u8>) -> Vec<u8> {
    // Derives the caller's namespace from the secret, validates it
    self.with_keystore(|ks| ks.sign(&secret, &key_id, &message).unwrap_or_default())
}
```

This works *if the secret arrives correctly*. When QtRO's dynamic dispatch corrupts the `secret` argument (bug #??), the provider cannot detect it — it receives what it thinks is the caller's secret but is actually stale data from a different caller's recent call.

### How C++ could improve this (not yet implemented):

A C++ module with access to `LogosModuleContext` could, in theory:

1. Query the call context to learn which caller is invoking this method
2. Maintain a per-caller cache of expected secrets or request signatures
3. Validate that the received `secret` argument matches what that specific caller should be sending
4. Reject corrupted calls with "caller mismatch" rather than "key not found"

This would still require the platform to expose caller identity through `LogosModuleContext`, but the C++ path is *architecturally closer* to making that possible.

## Recommendations

1. **For security-sensitive modules (keystores, cryptographic services):**
   - Use Rust cdylib if no external C library is required
   - If you need external C libraries, wrap them minimally and validate at every FFI boundary
   - Do NOT rely solely on argument values for isolation; validate caller identity at the platform level (future work)

2. **When debugging multi-caller issues:**
   - Add logging at the C-ABI boundary (C++ side of `logos_module_dispatch` call)
   - Log the exact bytes received, not just the interpreted value
   - Correlate with caller-side logs to detect where corruption occurs
   - Check QtRO dynamic dispatch logs (`QT_LOGGING_RULES="qt.remoteobjects*=true"`)

3. **For future platform improvements:**
   - Expose caller identity through `LogosModuleContext` APIs
   - Provide per-call request signing or integrity checking
   - Allow modules to opt into stricter validation of inbound arguments
   - Add tracing/correlation IDs to cross-process calls

## References

- Current architecture: `keystore_signer` (Rust cdylib) vs template in `nix flake init -t github:logos-co/logos-module-builder#with-external-lib`
- Known bug: cross-caller `bstr` corruption in QtRemoteObjects dynamic dispatch ([BUG_REPRODUCTION.md](../../BUG_REPRODUCTION.md))
- Caller isolation strategy: [keystore-signer-client documentation](../../keystore-signer-client/src/lib.rs)
