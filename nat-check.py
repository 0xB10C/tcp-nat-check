#!/usr/bin/env python3
"""
nat-check — TCP NAT mapping classifier.

Opens four TCP connections from the *same* local source port to four
(host, port) endpoints, asks each server what external (IP, port) it
observed, and classifies the NAT mapping behavior per RFC 4787:

    EIM    endpoint-independent          same external port everywhere; hole punching works
    ADM    address-dependent             same per dst IP, varies across IPs; hole punching fails
    APDM   address+port-dependent        varies per (dst IP, dst port); hole punching fails
    none   no NAT                        external addr == local addr; hole punching unnecessary

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

IP addresses are masked by default. Set NAT_CHECK_SHOW_IPS=1 to reveal them.

Checks IPv4 by default, and also checks IPv6 if all targets have AAAA records.
"""

import ipaddress
import json
import os
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


# --- IP masking -------------------------------------------------------

SHOW_IPS = os.environ.get("NAT_CHECK_SHOW_IPS", "0") in ("1", "true", "yes")

def _mask_ip(ip):
    """Replace an IP with a stable placeholder unless SHOW_IPS is set."""
    if SHOW_IPS:
        return ip
    if not hasattr(_mask_ip, "_cache"):
        _mask_ip._cache = {}
        _mask_ip._counter = 0
    if ip not in _mask_ip._cache:
        _mask_ip._counter += 1
        n = _mask_ip._counter
        if ":" in ip:
            _mask_ip._cache[ip] = f"x::x:{n}"
        else:
            _mask_ip._cache[ip] = f"x.x.x.{n}"
    return _mask_ip._cache[ip]


# --- socket plumbing --------------------------------------------------

def make_socket(family):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    s.settimeout(8.0)
    return s


def open_connection(family, local_port, ip, port):
    """Bind to local_port and connect to (ip, port). local_port=0 lets the
    kernel pick a free ephemeral port."""
    bind_addr = "0.0.0.0" if family == socket.AF_INET else "::"
    s = make_socket(family)
    s.bind((bind_addr, local_port))
    s.connect((ip, port))
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


def local_outbound_ip(remote_ip, family):
    """Discover the local IP the kernel would use to reach remote_ip."""
    s = socket.socket(family, socket.SOCK_DGRAM)
    try:
        s.connect((remote_ip, 9))
        return s.getsockname()[0]
    finally:
        s.close()


# --- resolution -------------------------------------------------------

def parse_targets(urls):
    targets = []
    for url in urls:
        p = urlparse(url)
        if p.scheme != "http" or not p.hostname or not p.port:
            raise SystemExit(f"bad URL: {url} (need http://host:port)")
        targets.append((p.hostname, p.port))
    return targets


def _is_v4_mapped(ip):
    """True for IPv4-mapped IPv6 addresses like ::ffff:1.2.3.4."""
    try:
        return ipaddress.IPv6Address(ip).ipv4_mapped is not None
    except (ipaddress.AddressValueError, ValueError):
        return False


def resolve_targets(targets):
    """Resolve targets for each address family.

    Returns ({family: [(host, port, ip), ...]}, [warnings]) for families where
    all targets resolve.

    IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) are skipped when resolving
    AF_INET6: macOS's getaddrinfo can return these alongside (or instead of)
    real AAAA results, and connecting to one falls back to IPv4 transport at
    the kernel level — the IPv6 socket actually sends v4 packets, so the
    server replies from its v4 listener and the classifier reports
    misleading 'IPv6' numbers."""
    result = {}
    warnings = []
    for family in (socket.AF_INET, socket.AF_INET6):
        resolved = []
        for host, port in targets:
            try:
                infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
            except socket.gaierror:
                break
            ip = None
            for info in infos:
                candidate = info[4][0]
                if family == socket.AF_INET6 and _is_v4_mapped(candidate):
                    warnings.append(
                        f"{host}: getaddrinfo returned IPv4-mapped address "
                        f"{candidate}; skipping (would silently use IPv4 transport)"
                    )
                    continue
                ip = candidate
                break
            if ip is None:
                break
            resolved.append((host, port, ip))
        if len(resolved) == len(targets):
            result[family] = resolved
    return result, warnings


# --- check logic ------------------------------------------------------

def run_check(resolved, family):
    """Run the NAT classification for one address family. Returns 0 on success."""
    family_label = "IPv4" if family == socket.AF_INET else "IPv6"
    print(BOLD(f"── {family_label} ──"))
    print()

    # 1. Open the first connection with a kernel-chosen ephemeral port.
    host0, port0, ip0 = resolved[0]
    try:
        s0 = open_connection(family, 0, ip0, port0)
    except OSError as e:
        print(RED(f"connect to {host0}:{port0} failed: {e}"))
        print()
        return 1
    local_port = s0.getsockname()[1]
    sockets = [s0]

    # 2. Open the remaining three on the SAME local port. Different
    #    destination 4-tuples keep this legal under SO_REUSEPORT.
    rebound = False
    for host, port, ip in resolved[1:]:
        try:
            s = open_connection(family, local_port, ip, port)
        except OSError as e:
            print(RED(f"connect to {host}:{port} from local port {local_port} failed: {e}"))
            for x in sockets:
                x.close()
            print()
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
            print()
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
        dst = f"{o['host']}:{o['port']} ({_mask_ip(o['dst_ip'])})"
        ext = f"{_mask_ip(o['ext_ip'])}:{o['ext_port']}"
        print(f"  {dst:<38} {ext:<26}")
    print()

    # 5. Sanity: external IP should be consistent across check-servers.
    ext_ips = {o["ext_ip"] for o in observations}
    if len(ext_ips) > 1:
        print(YELLOW(f"warning: external IP varies across servers: {sorted(_mask_ip(ip) for ip in ext_ips)}"))
        print(YELLOW("         multi-homed NAT or asymmetric routing."))
        print()

    # 6. Classify.
    try:
        my_local_ip = local_outbound_ip(observations[0]["dst_ip"], family)
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
            f"External address ({_mask_ip(my_local_ip)}:{local_port}) equals the local address. "
            "There is no NAT; hole punching is unnecessary. However, your home router "
            "may still have a stateful firewall that blocks unsolicited inbound "
            "connections. You may need to open the port on your router to be reachable."
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


# --- main -------------------------------------------------------------

def main(argv):
    if len(argv) != 5:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    targets = parse_targets(argv[1:5])
    families, warnings = resolve_targets(targets)

    for w in warnings:
        print(YELLOW(f"warning: {w}"), file=sys.stderr)

    if not families:
        print(RED("error: could not resolve all targets for any address family"),
              file=sys.stderr)
        return 1

    print(BOLD("nat-check") + DIM("  TCP NAT mapping classifier"))
    print()

    ret = 0
    for family, resolved in families.items():
        result = run_check(resolved, family)
        if result != 0:
            ret = result

    return ret


if __name__ == "__main__":
    sys.exit(main(sys.argv))
