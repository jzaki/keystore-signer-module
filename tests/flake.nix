{
  description = "Integration tests for keystore_signer — proves per-caller key isolation (test_caller_a cannot read or sign with test_caller_b's keys, and vice versa) over real Logos IPC via logoscore.";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    logos-logoscore-cli.url = "github:logos-co/logos-logoscore-cli";
    nixpkgs.follows = "logos-module-builder/nixpkgs";
  };

  outputs = inputs@{ self, logos-module-builder, logos-logoscore-cli, nixpkgs, ... }:
    let
      mkModule = logos-module-builder.lib.mkLogosModule;
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = fn: nixpkgs.lib.genAttrs systems fn;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};

          # The module under test — this repo's root.
          keystoreSigner = mkModule {
            src = ../.;
            configFile = ../metadata.json;
            flakeInputs = inputs;
          };

          callerA = mkModule {
            src = ./caller_a;
            configFile = ./caller_a/metadata.json;
            flakeInputs = { keystore_signer = keystoreSigner; } // inputs;
          };

          callerB = mkModule {
            src = ./caller_b;
            configFile = ./caller_b/metadata.json;
            flakeInputs = { keystore_signer = keystoreSigner; } // inputs;
          };

          # Merge all three modules into one LGPM-layout directory so
          # logoscore can discover them with a single -m flag.
          modulesDir = pkgs.runCommand "keystore-signer-test-modules-dir" { } ''
            mkdir -p $out
            for src in ${keystoreSigner.packages.${system}.install} ${callerA.packages.${system}.install} ${callerB.packages.${system}.install}; do
              cp -rL "$src"/modules/* $out/ 2>/dev/null || true
            done
          '';
        in
        {
          keystore_signer = keystoreSigner.packages.${system}.default;
          test_caller_a = callerA.packages.${system}.default;
          test_caller_b = callerB.packages.${system}.default;
          modules = modulesDir;
        }
      );

      checks = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          logoscore = logos-logoscore-cli.packages.${system}.default;
          modulesDir = self.packages.${system}.modules;
        in
        {
          isolation-test = pkgs.runCommand "keystore-signer-isolation-test"
            {
              nativeBuildInputs = [ logoscore pkgs.jq ]
                ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.qt6.qtbase ];
            } ''
            mkdir -p $out
            export QT_QPA_PLATFORM=offscreen
            export LOGOSCORE_CONFIG_DIR="$(mktemp -d)"
            DAEMON_PID=""
            cleanup() {
              logoscore --config-dir "$LOGOSCORE_CONFIG_DIR" stop >/dev/null 2>&1 || true
              [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
              rm -rf "$LOGOSCORE_CONFIG_DIR"
            }
            trap cleanup EXIT

            logoscore -D --config-dir "$LOGOSCORE_CONFIG_DIR" -m ${modulesDir} \
              >"$LOGOSCORE_CONFIG_DIR/daemon.log" 2>&1 &
            DAEMON_PID=$!
            ready=0
            for _i in $(seq 1 100); do
              if logoscore --config-dir "$LOGOSCORE_CONFIG_DIR" status >/dev/null 2>&1; then
                ready=1; break
              fi
              kill -0 "$DAEMON_PID" 2>/dev/null || break
              sleep 0.2
            done
            [ "$ready" = 1 ] || { echo "logoscore daemon failed to start:" >&2; cat "$LOGOSCORE_CONFIG_DIR/daemon.log" >&2; exit 1; }

            # load-module does not auto-resolve dependencies; load the
            # provider before its dependents.
            logoscore --config-dir "$LOGOSCORE_CONFIG_DIR" load-module keystore_signer
            logoscore --config-dir "$LOGOSCORE_CONFIG_DIR" load-module test_caller_a
            logoscore --config-dir "$LOGOSCORE_CONFIG_DIR" load-module test_caller_b

            fail() { echo "FAIL: $1" >&2; echo "--- daemon.log ---" >&2; cat "$LOGOSCORE_CONFIG_DIR/daemon.log" >&2; exit 1; }

            call() {
              # $1=module $2=method, rest=args; prints the bare .result value.
              # Deliberately not `set -e`-fatal on its own: capture the raw
              # response so a shape mismatch prints the actual payload
              # instead of aborting silently.
              module="$1"; method="$2"; shift 2
              raw=$(logoscore --json --config-dir "$LOGOSCORE_CONFIG_DIR" call "$module" "$method" "$@" 2>&1)
              rc=$?
              echo "call $module.$method(""$*"") -> rc=$rc raw=$raw" >&2
              if [ "$rc" -ne 0 ]; then
                fail "logoscore call $module.$method failed (rc=$rc): $raw"
              fi
              result=$(printf '%s' "$raw" | jq -r '.result' 2>&1) || fail "could not parse .result from: $raw"
              printf '%s' "$result"
            }

            # Method names below are the camelCase names declared in each
            # module's .lidl contract (the wire-level dispatch key) — NOT
            # the snake_case Rust trait method names codegen derives from
            # them (createKey vs create_key etc).

            echo "== A creates a key =="
            KEY_A=$(call test_caller_a createKey ed25519)
            [ -n "$KEY_A" ] && [ "$KEY_A" != "null" ] || fail "test_caller_a.createKey returned empty"

            echo "== B creates its own, different key =="
            KEY_B=$(call test_caller_b createKey secp256k1)
            [ -n "$KEY_B" ] && [ "$KEY_B" != "null" ] || fail "test_caller_b.createKey returned empty"
            [ "$KEY_A" != "$KEY_B" ] || fail "A and B were issued the same key id"

            echo "== A can sign with its own key =="
            SIG_A=$(call test_caller_a sign "$KEY_A" hello)
            [ -n "$SIG_A" ] && [ "$SIG_A" != "null" ] && [ "$SIG_A" != "" ] || fail "test_caller_a could not sign with its own key"

            echo "== B cannot sign with A's key id =="
            SIG_FORGED=$(call test_caller_b sign "$KEY_A" hello)
            if [ -n "$SIG_FORGED" ] && [ "$SIG_FORGED" != "null" ] && [ "$SIG_FORGED" != "" ]; then
              fail "test_caller_b produced a signature using test_caller_a's key id ($SIG_FORGED)"
            fi

            echo "== A cannot sign with B's key id =="
            SIG_FORGED2=$(call test_caller_a sign "$KEY_B" hello)
            if [ -n "$SIG_FORGED2" ] && [ "$SIG_FORGED2" != "null" ] && [ "$SIG_FORGED2" != "" ]; then
              fail "test_caller_a produced a signature using test_caller_b's key id ($SIG_FORGED2)"
            fi

            echo "== B's listKeys does not contain A's key id, and vice versa =="
            call test_caller_b listKeys \
              | { raw=$(cat); printf '%s' "$raw" | jq -e --arg k "$KEY_A" 'index($k) == null' >/dev/null \
                  || fail "test_caller_b.listKeys() leaked test_caller_a's key id ($raw)"; }
            call test_caller_a listKeys \
              | { raw=$(cat); printf '%s' "$raw" | jq -e --arg k "$KEY_B" 'index($k) == null' >/dev/null \
                  || fail "test_caller_a.listKeys() leaked test_caller_b's key id ($raw)"; }

            echo "== B cannot delete A's key id =="
            DEL_B=$(call test_caller_b deleteKey "$KEY_A")
            [ "$DEL_B" = "false" ] || fail "test_caller_b.deleteKey(A's key) did not return false ($DEL_B)"

            echo "== A's key still works after B's attempts =="
            SIG_A2=$(call test_caller_a sign "$KEY_A" hello)
            [ -n "$SIG_A2" ] && [ "$SIG_A2" != "null" ] && [ "$SIG_A2" != "" ] || fail "test_caller_a's key stopped working after B's attempts"

            echo "keystore_signer cross-caller isolation test passed" > $out/result.txt
          '';
        }
      );
    };
}
