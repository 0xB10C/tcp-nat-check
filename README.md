# tcp-nat-check

A tool to check the NAT type of your router. Helps to find out if TCP hole punching would work on your router.

## Pieces
 
- **`server/`** — a tiny Tokio Rust server that listens on two
  TCP ports and replies with the source IP:port the kernel observed.
  Deploy two of these on two distinct public hosts so the client has 4
  endpoints (2 hosts × 2 ports).
- **`nat_check.py`** — Python script that opens four TCP connections from
  the *same* local source port (via `SO_REUSEPORT`) and classifies the
  TCP NAT mapping behavior per RFC 4787: EIM / ADM / APDM / no-NAT. The
  same primitive Bitcoin Core would use to implement TCP hole-punching.

## Server
 
On each of two public hosts:
 
```bash
cd nat-check-server
cargo build --release
./target/release/nat-check 7770 7771
```
 
Or specify custom ports as positional args. Open both ports in the host
firewall and any cloud security group. The server runs as a foreground
process; for production wrap in a systemd unit.
 
## Client
 
```bash
python3 nat_check.py \
    http://hosta.example.com:7770 \
    http://hosta.example.com:7771 \
    http://hostb.example.com:7770 \
    http://hostb.example.com:7771
```
 
Output reports the local source port shared across all four connections,
the external (post-NAT) address each server saw, and a classification:
 
```
local source port: 51234

  destination                            external addr
  ────────────────────────────────────────────────────────────────
  hosta.example.com:7770 (x.x.x.1)      x.x.x.3:51234
  hosta.example.com:7771 (x.x.x.1)      x.x.x.3:51234
  hostb.example.com:7770 (x.x.x.2)      x.x.x.3:51234
  hostb.example.com:7771 (x.x.x.2)      x.x.x.3:51234

classification: ENDPOINT-INDEPENDENT MAPPING (EIM)
```

IP addresses are masked by default so output is safe to share publicly.
To show real IPs, set `NAT_CHECK_SHOW_IPS=1`:

```bash
NAT_CHECK_SHOW_IPS=1 python3 nat_check.py ...
```
 
## Classification meanings
 
- **EIM** (endpoint-independent) — same external port everywhere → hole
  punching has a strong chance of working.
- **ADM** (address-dependent) — same per destination IP, different
  across IPs → hole punching fails. The coordinator only knows the
  external port your NAT assigned for the coordinator's IP, but your NAT
  will assign a different, unpredictable port when you connect to a new
  peer IP.
- **APDM** (address+port-dependent, "symmetric") — varies per
  `(dst_ip, dst_port)` → hole punching fails for the same reason as ADM.
  Typical of CGNAT, mobile carriers, and restrictive enterprise networks.
- **no NAT** — external address equals local address → hole punching
  unnecessary; just listen normally.

If the script prints a `kernel rebound port` warning, `SO_REUSEPORT` was
not honored (older Linux, Windows, sandboxed environments). The result
is unreliable on that platform; rerun on a normal Linux/macOS host.

## NixOS

This repository provides a Nix flake with a NixOS module for running the server.

### Running directly with Nix

```bash
nix run github:0xb10c/tcp-nat-check
nix run github:0xb10c/tcp-nat-check -- 8080 8081  # custom ports
```

### NixOS module

Add the flake to your NixOS configuration inputs and import the module:

```nix
{
  inputs.tcp-nat-check.url = "github:0xb10c/tcp-nat-check";

  outputs = { self, nixpkgs, tcp-nat-check, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        tcp-nat-check.nixosModules.default
        {
          services.nat-check-server = {
            enable = true;
            # portA = 7770;       # default
            # portB = 7771;       # default
            # openFirewall = true; # open both ports in the firewall
          };
        }
      ];
    };
  };
}
```
