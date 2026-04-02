{
  description = "OpenTelemetry Collector development";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];

      forEachSupportedSystem = f: nixpkgs.lib.genAttrs supportedSystems (system: f {
        pkgs = import nixpkgs { inherit system; config.allowUnfree = true; };
      });
    in
    {
      devShells = forEachSupportedSystem ({ pkgs }: {
        default = pkgs.mkShell {
          name = "otel-dev";

          # Prevents launch errors with delve debugger
          hardeningDisable = [ "fortify" ];

          buildInputs = with pkgs; [
            # Go development
            go
            go-mockery

            # Utils & infra
            just
            openssl
            docker-compose
            openldap
            terraform
            vault
            renovate

            # Lint
            shellcheck
            golangci-lint
          ];
        };
      });
    };
}
