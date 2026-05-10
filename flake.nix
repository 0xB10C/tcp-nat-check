{
  description = "tcp-nat-check — classify TCP NAT mapping behavior";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          nat-check-server = pkgs.rustPlatform.buildRustPackage {
            pname = "nat-check-server";
            version = "0.1.0";
            src = ./server;
            cargoLock.lockFile = ./server/Cargo.lock;
            meta.mainProgram = "nat-check-server";
          };

          default = self.packages.${system}.nat-check-server;
        }
      );

      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.nat-check-server;
        in
        {
          options.services.nat-check-server = {
            enable = lib.mkEnableOption "nat-check-server";

            package = lib.mkPackageOption self.packages.${pkgs.stdenv.hostPlatform.system} "nat-check-server" { };

            portA = lib.mkOption {
              type = lib.types.port;
              default = 7770;
              description = "First listen port.";
            };

            portB = lib.mkOption {
              type = lib.types.port;
              default = 7771;
              description = "Second listen port.";
            };

            openFirewall = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = "Whether to open both ports in the firewall.";
            };
          };

          config = lib.mkIf cfg.enable {
            systemd.services.nat-check-server = {
              description = "TCP NAT check server";
              wantedBy = [ "multi-user.target" ];
              after = [ "network.target" ];

              serviceConfig = {
                ExecStart = "${lib.getExe cfg.package} ${toString cfg.portA} ${toString cfg.portB}";
                DynamicUser = true;
                Restart = "on-failure";
                RestartSec = 5;

                # Hardening
                CapabilityBoundingSet = "";
                NoNewPrivileges = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                PrivateDevices = true;
                PrivateTmp = true;
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectControlGroups = true;
                RestrictNamespaces = true;
                RestrictSUIDSGID = true;
                MemoryDenyWriteExecute = true;
              };
            };

            networking.firewall.allowedTCPPorts =
              lib.mkIf cfg.openFirewall [ cfg.portA cfg.portB ];
          };
        };
    };
}
