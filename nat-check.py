#!/usr/bin/env python3
"""
nat-check — TCP NAT mapping classifier.

Opens four TCP connections from the *same* local source port to four
(host, port) endpoints, asks each server what external (IP, port) it
observed, and classifies the NAT mapping behavior per RFC 4787:

    EIM    endpoint-independent          same external port everywhere
    ADM    address-dependent             same per dst IP, varies across IPs
    APDM   address+port-dependent        varies per (dst IP, dst port)  ("symmetric")
    none   no NAT                        external addr == local addr

Pair with the matching nat-check-server Rust server running on two distinct
public hosts, on two ports each.

Usage:
    python3 nat_check.py URL_A1 URL_A2 URL_B1 URL_B2

Example:
    python3 nat_check.py \\
        http://hosta.example.com:7770 \\
        http://hosta.example.com:7771 \\
        http://hostb.example.com:7770 \\
        http://hostb.example.com:7771

"""

import json
import socket
import sys
import textwrap
from urllib.parse import urlparse


# --- terminal colors (only when stdout is a TTY) ----------------------

def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if sys.stdout.isatty() else s

GREEN  = lambda s: _c("32", s)
RED    = lambda s: _c("31", s)
YELLOW = lambda s: _c("33", s)
DIM    = lambda s: _c("2",  s)
BOLD   = lambda s: _c("1",  s)


# --- socket plumbing --------------------------------------------------

def make_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    s.settimeout(8.0)
    return s


def open_connection(local_port, host, port):
    """Bind to (0.0.0.0, local_port) and connect. local_port=0 lets the
    kernel pick a free ephemeral port."""
    s = make_socket()
    s.bind(("0.0.0.0", local_port))
    s.connect((host, port))
    return s


def http_query(sock, host):
    """Send a tiny HTTP/1.0 GET on an open socket; return parsed JSON body."""
    req = (f"GET / HTTP/1.0\r\n"
           f"Host: {host}\r\n"
           f"Connection: close\r\n\r\n").encode()
    sock.sendall(req)
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    sep = buf.find(b"\r\n\r\n")
    if sep < 0:
        raise RuntimeError("malformed HTTP response (no header/body separator)")
    return json.loads(buf[sep + 4:].decode("utf-8", errors="replace").strip())


def local_outbound_ip(remote_ip):
    """Discover the local IP the kernel would use to reach remote_ip."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((remote_ip, 9))
        return s.getsockname()[0]
    finally:
        s.close()


# --- main -------------------------------------------------------------

def parse_targets(urls):
    targets = []
    for url in urls:
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname or not p.port:
            raise SystemExit(f"bad URL: {url} (need scheme://host:port)")
        targets.append((p.hostname, p.port))
    return targets


def main(argv):
    if len(argv) != 5:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    targets = parse_targets(argv[1:5])

    # Resolve hostnames once so we can group by destination IP later.
    resolved = []
    for host, port in targets:
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            print(f"DNS failure for {host}: {e}", file=sys.stderr)
            return 1
        resolved.append((host, port, ip))

    print(BOLD("nat-check") + DIM("  TCP NAT mapping classifier"))
    print()

    # 1. Open the first connection with a kernel-chosen ephemeral port.
    try:
        s0 = open_connection(0, resolved[0][0], resolved[0][1])
    except OSError as e:
        print(RED(f"connect to {resolved[0][0]}:{resolved[0][1]} failed: {e}"))
        return 1
    local_port = s0.getsockname()[1]
    sockets = [s0]

    # 2. Open the remaining three on the SAME local port. Different
    #    destination 4-tuples keep this legal under SO_REUSEPORT.
    rebound = False
    for host, port, _ip in resolved[1:]:
        try:
            s = open_connection(local_port, host, port)
        except OSError as e:
            print(RED(f"connect to {host}:{port} from local port {local_port} failed: {e}"))
            for x in sockets:
                x.close()
            return 1
        actual = s.getsockname()[1]
        if actual != local_port:
            rebound = True
            print(YELLOW(
                f"warning: kernel did not honor SO_REUSEPORT — "
                f"this socket bound to {actual} instead of {local_port}"
            ))
        sockets.append(s)
    if rebound:
        print(YELLOW("  the comparison below is no longer apples-to-apples; results unreliable."))
        print()

    # 3. Query each open socket; close as we go.
    observations = []
    for sock, (host, port, ip) in zip(sockets, resolved):
        try:
            obs = http_query(sock, host)
        except Exception as e:
            print(RED(f"query {host}:{port} failed: {e}"))
            for x in sockets:
                x.close()
            return 1
        finally:
            sock.close()
        observations.append({
            "host": host, "port": port, "dst_ip": ip,
            "ext_ip": obs["observed_ip"], "ext_port": int(obs["observed_port"]),
        })

    # 4. Print the raw observations.
    print(f"local source port: {BOLD(str(local_port))}")
    print()
    print(DIM(f"  {'destination':<38} {'external addr':<26}"))
    print(DIM("  " + "─" * 64))
    for o in observations:
        dst = f"{o['host']}:{o['port']} ({o['dst_ip']})"
        ext = f"{o['ext_ip']}:{o['ext_port']}"
        print(f"  {dst:<38} {ext:<26}")
    print()

    # 5. Sanity: external IP should be consistent across check-servers.
    ext_ips = {o["ext_ip"] for o in observations}
    if len(ext_ips) > 1:
        print(YELLOW(f"warning: external IP varies across servers: {sorted(ext_ips)}"))
        print(YELLOW("         multi-homed NAT or asymmetric routing."))
        print()

    # 6. Classify.
    try:
        my_local_ip = local_outbound_ip(observations[0]["dst_ip"])
    except OSError:
        my_local_ip = None

    ext_ports = [o["ext_port"] for o in observations]
    unique_ports = set(ext_ports)
    no_nat = (
        len(ext_ips) == 1
        and my_local_ip is not None
        and next(iter(ext_ips)) == my_local_ip
        and all(p == local_port for p in ext_ports)
    )

    if no_nat:
        label = "NO NAT"
        color = GREEN
        detail = (
            f"External address ({my_local_ip}:{local_port}) equals the local address. "
            "Your host is directly reachable; hole punching is unnecessary. Just listen "
            "on the Bitcoin P2P port and ensure your firewall accepts inbound TCP."
        )
    elif len(unique_ports) == 1:
        label = "ENDPOINT-INDEPENDENT MAPPING (EIM)"
        color = GREEN
        detail = (
            "All four destinations saw the same external port. Your NAT maps "
            "(internal IP, internal port) to a single external port regardless of "
            "destination. TCP hole punching has a strong chance of working: a "
            "coordinator can reliably tell a peer which external port to send to."
        )
    else:
        by_dst_ip = {}
        for o in observations:
            by_dst_ip.setdefault(o["dst_ip"], []).append(o["ext_port"])
        same_per_ip = all(len(set(ps)) == 1 for ps in by_dst_ip.values())
        if same_per_ip and len(by_dst_ip) >= 2:
            label = "ADDRESS-DEPENDENT MAPPING (ADM)"
            color = RED
            detail = (
                "Same external port for all destinations sharing a destination IP, "
                "but a different external port per destination IP. TCP hole punching "
                "will not work: a coordinator only knows the external port your NAT "
                "assigned for the coordinator's IP, but your NAT will assign a "
                "different, unpredictable port when you connect to a new peer IP."
            )
        else:
            label = "ADDRESS+PORT-DEPENDENT MAPPING (APDM, 'symmetric')"
            color = RED
            detail = (
                "External port varies per destination (IP, port). TCP hole punching "
                "is very unlikely to work for you: the coordinator cannot predict the "
                "external port your NAT will assign for any given peer. This pattern "
                "is typical of CGNAT, mobile carriers, and restrictive enterprise "
                "networks."
            )

    print(BOLD("classification: ") + color(BOLD(label)))
    print()
    for line in textwrap.wrap(detail, width=78):
        print("  " + line)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
