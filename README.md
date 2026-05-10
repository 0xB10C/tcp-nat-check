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
  hosta.example.com:7770 (1.2.3.4)       5.6.7.8:51234
  hosta.example.com:7771 (1.2.3.4)       5.6.7.8:51234
  hostb.example.com:7770 (9.10.11.12)    5.6.7.8:51234
  hostb.example.com:7771 (9.10.11.12)    5.6.7.8:51234
 
classification: ENDPOINT-INDEPENDENT MAPPING (EIM)
```
 
## Classification meanings
 
- **EIM** (endpoint-independent) — same external port everywhere → hole
  punching has a strong chance of working.
- **ADM** (address-dependent) — same per destination IP, different
  across IPs → the simple two-peer hole punch may still work (the port a
  peer needs is the one your NAT used the first time you contacted that
  peer's IP); less robust than EIM.
- **APDM** (address+port-dependent, "symmetric") — varies per
  `(dst_ip, dst_port)` → coordinator cannot predict your external port
  for any given peer; hole punching fails. Typical of CGNAT, mobile
  carriers, and restrictive enterprise networks.
- **no NAT** — external address equals local address → hole punching
  unnecessary; just listen normally.

If the script prints a `kernel rebound port` warning, `SO_REUSEPORT` was
not honored (older Linux, Windows, sandboxed environments). The result
is unreliable on that platform; rerun on a normal Linux/macOS host.
 

