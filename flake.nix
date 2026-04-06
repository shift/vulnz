{
  description = "vulnz - Vulnerability data aggregator for EU CRA compliance";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "vulnz";
          version = "1.0.0";
          
          src = ./.;

          # Update this hash via `nix run nixpkgs#nix-prefetch-go` if go.mod changes
          vendorHash = pkgs.lib.fakeHash;

          subPackages = [ "cmd/vulnz" ];

          # Optional: Linker flags to embed version information
          ldflags = [
            "-s" "-w"
            "-X main.Version=1.0.0"
          ];

          meta = with pkgs.lib; {
            description = "Concurrent vulnerability data aggregator with EU Cyber Resilience Act tracking";
            homepage = "https://github.com/shift/vulnz";
            license = licenses.agpl3Only;
            platforms = platforms.linux ++ platforms.darwin;
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            gnumake
            golangci-lint
            glab     # GitLab CLI (gitlab.opencode.de)
            gh       # GitHub CLI
            tea      # Forgejo/Gitea CLI (Codeberg)
          ];
          
          shellHook = ''
            echo "vulnz development environment loaded."
            export VULNZ_LOG_LEVEL=debug
          '';
        };
      }
    );
}
