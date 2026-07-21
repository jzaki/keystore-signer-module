{
  description = "keystore_signer — per-caller isolated signing keystore (Ed25519 / secp256k1 / BLS12-381) for Logos modules";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
  };

  outputs = inputs@{ logos-module-builder, ... }:
    logos-module-builder.lib.mkLogosModule {
      src = ./.;
      configFile = ./metadata.json;
      flakeInputs = inputs;
    };
}
