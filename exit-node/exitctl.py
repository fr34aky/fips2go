#!/usr/bin/env python3
"""fips2go exit node: allow-list, addresses, firewall and fips config.

Standard library only. The entrypoint calls it; nothing here touches the
system — every subcommand prints, so all of it can be tested.

    exitctl.py addrs NPUB...              npub  fips-address  inner-ipv4
    exitctl.py clients ALLOWLIST          ifname npub fips-address inner-ipv4
    exitctl.py publish SPEC               mesh-port host port, per published service
    exitctl.py public-ip LOOKUP           this network's public IPv4 address(es),
                                          one line; LOOKUP "" = the defaults
    exitctl.py nft [--open] [--open-block-tcp=PORTS] ALLOWLIST WAN PUBLISH PUBLIC_IPS [CIDR..]
                                          the nftables ruleset (stdout)
    exitctl.py open-plan STATE KNOCKS COUNTERS CLIENTS MAX IDLE_SECS
                                          open mode: who to admit and who to
                                          drop now, and the new state (stdout)
    exitctl.py nft-public-ip [ADDR..]     nft script that swaps the blocked
                                          public addresses (stdout)
    exitctl.py fips-yaml [--dns] PEERS    the fips daemon config (stdout)

Addresses (the contract with the phone, shim/src/exit.rs `inner_ipv4`):

    fips address = fd || SHA-256(32-byte x-only pubkey)[0:15]
    inner IPv4   = 100.64.0.0 | ((a[1] << 16 | a[2] << 8 | a[3]) & 0x3fffff)

A fips address is bound to its npub by fips itself: a session only
completes when the key it proved hashes to the address it claimed, and the
receiver writes that address into every packet as the source. So "came in
on fips0 from address X" means "sent by the holder of X's npub", and every
rule below can key on it.
"""

import concurrent.futures
import hashlib
import ipaddress
import json
import re
import sys
import time
import urllib.request

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# Never reachable through the exit: the host's and the container's own
# networks, other clients (100.64/10), and everything not unicast internet.
BLOCKED_V4 = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/3",
]

# Never a published destination: the container itself, the clients' inner
# addresses (routed into their tunnels), and nothing that is not unicast.
PUBLISH_REFUSED_V4 = ["0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "224.0.0.0/3"]
# Mesh ports a published service may not take.
RESERVED_PORTS = {53: "the exit's DNS"}

# Where the exit asks for its own network's public IPv4 address
# (PUBLIC_IP_LOOKUP). IPv4-only endpoints, over HTTPS, run by different
# operators. Every valid answer is blocked, so a wrong or lying source can
# only add a block, never lift one.
DEFAULT_PUBLIC_IP_LOOKUP = [
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com",
    "https://v4.ident.me",
]
MAX_LOOKUP_URLS = 8
LOOKUP_TIMEOUT = 5

# The public test-mesh bootstrap servers the app peers with by default, so
# the exit joins the same mesh as a phone with default settings.
DEFAULT_PEERS = [
    "npub1260n42s06vzc7796w0fh3ny7zcpw6tlk4gq3940gmfrzl5c9pv2s3657q8@test-de01.fips.network:2121",
    "npub1u0z26dc4qeneu5rvwvmpfhtwh3522ed6rlgxr9jarrfnjrc6ew4qxjysrs@test-uk01.fips.network:2121",
]


class ConfigError(Exception):
    pass


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def npub_to_pubkey(npub: str) -> bytes:
    s = npub.strip()
    if s != s.lower() and s != s.upper():
        raise ConfigError(f"not an npub (mixed case): {npub!r}")
    s = s.lower()
    hrp, sep, data = s.rpartition("1")
    if hrp != "npub" or not sep or len(data) < 7 or any(c not in CHARSET for c in data):
        raise ConfigError(f"not an npub: {npub!r}")
    values = [CHARSET.index(c) for c in data]
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    if _polymod(expanded + values) != 1:
        raise ConfigError(f"npub checksum does not match (typo?): {npub!r}")
    acc, bits, out = 0, 0, bytearray()
    for v in values[:-6]:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if len(out) != 32 or (bits >= 5 or (acc & ((1 << bits) - 1))):
        raise ConfigError(f"npub is not a 32-byte key: {npub!r}")
    return bytes(out)


def fips_address(npub: str) -> ipaddress.IPv6Address:
    digest = hashlib.sha256(npub_to_pubkey(npub)).digest()
    return ipaddress.IPv6Address(b"\xfd" + digest[:15])


def inner_ipv4(addr: ipaddress.IPv6Address) -> ipaddress.IPv4Address:
    a = addr.packed
    bits = (a[1] << 16 | a[2] << 8 | a[3]) & 0x3FFFFF
    return ipaddress.IPv4Address(0x64400000 | bits)


def parse_allowlist(text: str):
    """npubs from an allow-list: one per line, `#` comments, anything after
    the npub on a line is a free-form label. Every line that is not blank or
    a comment must be a valid npub — a typo stops the exit rather than
    silently allowing fewer (or, worse, other) clients."""
    seen, out = set(), []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        npub = line.split()[0]
        try:
            npub_to_pubkey(npub)
        except ConfigError as e:
            raise ConfigError(f"allow-list line {n}: {e}") from None
        npub = npub.lower()
        if npub not in seen:
            seen.add(npub)
            out.append(npub)
    return out


def clients(npubs):
    """(ifname, npub, fips address, inner IPv4) per allowed client. Two
    clients whose inner addresses collide (22 bits, so possible) are refused:
    their replies could not be told apart."""
    rows, by_inner = [], {}
    for i, npub in enumerate(npubs):
        addr = fips_address(npub)
        inner = inner_ipv4(addr)
        if inner in by_inner:
            raise ConfigError(
                f"{npub} and {by_inner[inner]} share the inner address {inner}; "
                "only one of them can use this exit"
            )
        by_inner[inner] = npub
        rows.append((f"fx{i}", npub, addr, inner))
    return rows


def _ifname(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name):
        raise ConfigError(f"not an interface name: {name!r}")
    return name


def _port(text: str, spec: str) -> int:
    port = int(text)
    if not 1 <= port <= 65535:
        raise ConfigError(f"port out of range in PUBLISH entry {spec!r}")
    return port


def parse_publish(text: str):
    """(mesh port, IPv4 host, port) per published service, from PUBLISH:
    `MESH_PORT=HOST:PORT` (or `MESH_PORT=HOST` for the same port), space or
    comma separated, TCP only. HOST is an IPv4 literal: a name would be
    resolved by Docker's resolver on every connection, and could change
    under the operator's feet. Private addresses are allowed here — reaching
    them is the point — but only through the relay this list starts, never
    by forwarding: the forward chain's block on private ranges is untouched.
    One bad entry stops the exit."""
    out, seen = [], set()
    for spec in _split_specs(text):
        m = re.fullmatch(r"(\d{1,5})=([0-9.]+)(?::(\d{1,5}))?", spec)
        if not m:
            raise ConfigError(f"PUBLISH entry must be MESH_PORT=IPv4:PORT: {spec!r}")
        mesh_port = _port(m.group(1), spec)
        try:
            host = ipaddress.IPv4Address(m.group(2))
        except ValueError:
            raise ConfigError(f"not an IPv4 address in PUBLISH entry {spec!r}") from None
        port = _port(m.group(3) or m.group(1), spec)
        if mesh_port in RESERVED_PORTS:
            raise ConfigError(f"PUBLISH entry {spec!r}: port {mesh_port} is {RESERVED_PORTS[mesh_port]}")
        if mesh_port in seen:
            raise ConfigError(f"PUBLISH entry {spec!r}: mesh port {mesh_port} is published twice")
        if host.is_unspecified or host == ipaddress.IPv4Address("255.255.255.255") or any(
            host in ipaddress.IPv4Network(n) for n in PUBLISH_REFUSED_V4
        ):
            raise ConfigError(f"PUBLISH entry {spec!r}: {host} cannot be published")
        seen.add(mesh_port)
        out.append((mesh_port, host, port))
    return out


def parse_lookup(text: str):
    """URLs from PUBLIC_IP_LOOKUP: empty = the defaults, "off" = none (no
    public-address block), else http(s) URLs separated by spaces or commas.
    One bad entry stops the exit."""
    text = text.strip()
    if not text:
        return list(DEFAULT_PUBLIC_IP_LOOKUP)
    if text == "off":
        return []
    urls = _split_specs(text)
    if len(urls) > MAX_LOOKUP_URLS:
        raise ConfigError(f"PUBLIC_IP_LOOKUP: at most {MAX_LOOKUP_URLS} URLs")
    for url in urls:
        if not re.fullmatch(r"https?://[A-Za-z0-9.:\[\]_~/%?=&+-]+", url):
            raise ConfigError(f"PUBLIC_IP_LOOKUP entry must be an http(s) URL or off: {url!r}")
    return urls


def public_ipv4(answer: str):
    """The address in a lookup service's answer, if it is one this exit could
    be reached at from the internet: a global unicast IPv4. Anything else —
    private, CGNAT, an IPv6 address, an error page — is None."""
    try:
        addr = ipaddress.IPv4Address(answer.strip())
    except ValueError:
        return None
    if not addr.is_global or addr.is_multicast or any(
        addr in ipaddress.IPv4Network(n) for n in BLOCKED_V4
    ):
        return None
    return addr


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "fips2go-exit"})
    with urllib.request.urlopen(req, timeout=LOOKUP_TIMEOUT) as r:
        return r.read(64).decode("ascii", "replace")


def public_ips(urls, fetch=_fetch, log=lambda _m: None):
    """Every valid public IPv4 the lookup services report, sorted. All are
    asked at once. Raises when none gives one: the caller decides whether
    that stops the exit (at start) or keeps the last answer (later)."""
    found, errors = set(), []
    if not urls:
        return []
    with concurrent.futures.ThreadPoolExecutor(len(urls)) as pool:
        for url, fut in [(u, pool.submit(fetch, u)) for u in urls]:
            try:
                answer = fut.result()
            except Exception as e:  # noqa: BLE001 — any failure is one source's
                errors.append(f"{url}: {e}")
                continue
            addr = public_ipv4(answer)
            if addr is None:
                errors.append(f"{url}: not a public IPv4 address: {answer.strip()[:40]!r}")
            else:
                found.add(addr)
    if not found:
        raise ConfigError("no lookup service gave a public IPv4 address" + "".join(f"\n  {e}" for e in errors))
    for e in errors:
        log(e)
    return sorted(found)


def nft_public_ip(addrs):
    """Swap the blocked public addresses in one atomic transaction, leaving
    the rest of the firewall as it is."""
    out = "flush set inet fips_exit blocked_dyn\n"
    addrs = [str(ipaddress.IPv4Address(a)) for a in addrs]
    if addrs:
        out += f"add element inet fips_exit blocked_dyn {{ {', '.join(addrs)} }}\n"
    return out


# TCP MSS through a tunnel, IPv4 (the phone's `exit::MSS_IPV4`): a fips hop
# carries at least 1280-byte packets; minus 40 for the outer IPv6 header that
# leaves 1240 for the inner packet, minus 20 + 20 for its IPv4 and TCP
# headers. A Linux ip6tnl does not fragment the outer packet, so a bigger
# segment would be lost on such a hop.
TCP_MSS = 1200


# Open mode (OPEN=1): TCP ports clients admitted without being on the
# allow-list may not connect to. 25 is mail between servers, which nobody
# sends from a phone and every spammer sends from an open exit.
DEFAULT_OPEN_BLOCK_TCP = [25]
# A fips address that sent a first packet waits here to be admitted.
KNOCK_TIMEOUT = 60
KNOCK_SIZE = 256
# DNS queries per second a single address may send in open mode, where the
# resolver answers the whole mesh.
OPEN_DNS_RATE = 20


def parse_ports(text: str):
    """TCP ports from a comma or space separated list ("" = none)."""
    out = []
    for spec in _split_specs(text):
        if not re.fullmatch(r"\d{1,5}", spec) or not 1 <= int(spec) <= 65535:
            raise ConfigError(f"not a TCP port: {spec!r}")
        if int(spec) not in out:
            out.append(int(spec))
    return out


def nft_ruleset(rows, wan: str, extra_blocked=(), published=(), public=(), open_mode=False,
                open_block_tcp=()):
    """The exit's whole firewall, as one atomic nft script.

    - Mesh side (fips0): new traffic only from allowed clients' fips
      addresses — IPv4-in-IPv6 for their tunnel, DNS, and TCP to the
      published ports. Everything else new on fips0 is dropped: the exit
      offers nothing to the rest of the mesh.
    - Forwarding is default-deny. A client's tunnel may send only from that
      client's own inner address (no spoofing another client), only out of
      the WAN interface, and never to a blocked destination — nor to this
      network's own public address (blocked_dyn, kept current by the
      entrypoint), which would reach the router and, through its NAT
      loopback, port-forwarded LAN services. Nothing else is
      forwarded: not IPv6, not mesh to mesh, not WAN to a client unless it
      is a reply.
    - TCP SYNs through a tunnel, both ways, get their MSS lowered to
      TCP_MSS (the phone clamps to the same), so an inner packet fits a
      1280-byte mesh packet once wrapped.
    - Tunnel interfaces reach nothing on the exit itself.
    - Open mode (`open_mode`): any fips address may become a client. Its
      first IPv4-in-IPv6 packet or DNS query puts it in `knock6`, where the
      entrypoint's loop finds it, builds its tunnel and adds it to `open6`
      (and to `client_src`/`clients4`, like a listed client). Such a client
      gets internet and DNS and nothing else: the published services stay
      with the allow-list (`clients6`), and `open_block_tcp` ports are
      refused. DNS is answered for the whole mesh, rate-limited per address.
    """
    wan = _ifname(wan)
    blocked = BLOCKED_V4 + [str(ipaddress.IPv4Network(c, strict=False)) for c in extra_blocked]
    addrs6 = ", ".join(str(r[2]) for r in rows)
    pairs = ", ".join(f'"{r[0]}" . {r[3]}' for r in rows)
    inners = ", ".join(str(r[3]) for r in rows)
    set6 = f"elements = {{ {addrs6} }}" if rows else ""
    setpair = f"elements = {{ {pairs} }}" if rows else ""
    set4 = f"elements = {{ {inners} }}" if rows else ""
    ports = ", ".join(str(p[0]) for p in published)
    setports = f"elements = {{ {ports} }}" if published else ""
    pub = ", ".join(str(ipaddress.IPv4Address(a)) for a in public)
    setpub = f"elements = {{ {pub} }}" if public else ""
    open_sets = open_mesh = open_fwd = ""
    if open_mode:
        open_sets = f"""
	set open6 {{
		type ipv6_addr
	}}
	set knock6 {{
		type ipv6_addr
		size {KNOCK_SIZE}
		flags dynamic,timeout
		timeout {KNOCK_TIMEOUT}s
	}}
	set dnsrate {{
		type ipv6_addr
		size 4096
		flags dynamic,timeout
		timeout 1m
	}}
"""
        # A full knock set makes `add` fail, so the rule does not match and
        # the packet falls through to the chain's drop: bounded either way.
        open_mesh = f"""		ip6 saddr @open6 meta l4proto 4 accept
		ip6 saddr fd00::/8 meta l4proto 4 add @knock6 {{ ip6 saddr }} drop
		ip6 saddr fd00::/8 udp dport 53 add @dnsrate {{ ip6 saddr limit rate over {OPEN_DNS_RATE}/second burst {OPEN_DNS_RATE * 2} packets }} drop
		ip6 saddr fd00::/8 udp dport 53 add @knock6 {{ ip6 saddr }} accept
		ip6 saddr fd00::/8 udp dport 53 accept
"""
        if open_block_tcp:
            ports_blocked = ", ".join(str(int(p)) for p in open_block_tcp)
            open_fwd = f"""		iifname "fxo*" tcp dport {{ {ports_blocked} }} drop
"""
    return f"""\
table inet fips_exit
delete table inet fips_exit
table inet fips_exit {{
	set clients6 {{
		type ipv6_addr
		{set6}
	}}
	set client_src {{
		type ifname . ipv4_addr
		{setpair}
	}}
	set clients4 {{
		type ipv4_addr
		{set4}
	}}
	set published_tcp {{
		type inet_service
		{setports}
	}}
	set blocked4 {{
		type ipv4_addr
		flags interval
		auto-merge
		elements = {{ {", ".join(blocked)} }}
	}}
	set blocked_dyn {{
		type ipv4_addr
		{setpub}
	}}
{open_sets}
	chain input {{
		type filter hook input priority filter; policy accept;
		iifname "fips0" jump mesh_in
		iifname "fx*" drop
	}}

	chain mesh_in {{
		ct state established,related accept
		ct state invalid drop
		ip6 saddr @clients6 meta l4proto 4 accept
		ip6 saddr @clients6 udp dport 53 accept
		ip6 saddr @clients6 tcp dport @published_tcp accept
{open_mesh}		icmpv6 type {{ echo-request, packet-too-big, destination-unreachable, time-exceeded, parameter-problem }} accept
		drop
	}}

	chain forward {{
		type filter hook forward priority filter; policy drop;
		ct state invalid drop
		iifname "fx*" tcp flags & (syn | rst) == syn tcp option maxseg size > {TCP_MSS} tcp option maxseg size set {TCP_MSS}
		oifname "fx*" tcp flags & (syn | rst) == syn tcp option maxseg size > {TCP_MSS} tcp option maxseg size set {TCP_MSS}
{open_fwd}		iifname "fx*" oifname "{wan}" iifname . ip saddr @client_src ip daddr != @blocked4 ip daddr != @blocked_dyn accept
		iifname "{wan}" oifname "fx*" ct state established,related accept
	}}

	chain postrouting {{
		type nat hook postrouting priority srcnat; policy accept;
		oifname "{wan}" ip saddr @clients4 masquerade
	}}
}}
"""


def knocked(nft_json: str):
    """The addresses in `nft -j list set inet fips_exit knock6`."""
    out = []
    try:
        doc = json.loads(nft_json or "{}")
    except ValueError:
        return out
    for item in doc.get("nftables", []):
        for elem in (item.get("set") or {}).get("elem", []):
            # With a timeout an element is {"elem": {"val": addr, ...}}.
            if isinstance(elem, dict):
                elem = (elem.get("elem") or {}).get("val")
            if isinstance(elem, str):
                out.append(elem)
    return out


def plan_open(state, knocks, counters, now, static_rows, max_clients, idle_secs):
    """Open mode's bookkeeping, as a pure function.

    `state` maps a client's fips address to {dev, inner, rx, seen}: the
    clients admitted so far. `knocks` are addresses that sent a first packet;
    `counters` the received-packet count of each open tunnel now.

    Returns (actions, new state, notes). An action is ("ADD" | "DEL", dev,
    fips address, inner address); the entrypoint carries them out.

    - A client whose tunnel received nothing for `idle_secs` is dropped, so
      the table holds people using the exit, not everyone who ever tried.
    - A knock is admitted unless the exit is full (`max_clients`), or its
      inner address is taken by a listed client or another open one (22 bits:
      their replies could not be told apart, so the first one keeps it).
    - Only fd00::/8 can knock, and never a listed client's own address.
    """
    actions, notes = [], []
    clients = {a: dict(c) for a, c in state.get("clients", {}).items()}
    for addr in sorted(clients):
        c = clients[addr]
        rx = counters.get(c["dev"])
        if rx is None:
            # The tunnel is gone (removed by hand?): forget it cleanly.
            actions.append(("DEL", c["dev"], addr, c["inner"]))
            del clients[addr]
            continue
        if rx != c["rx"]:
            c["rx"], c["seen"] = rx, now
        elif now - c["seen"] > idle_secs:
            actions.append(("DEL", c["dev"], addr, c["inner"]))
            del clients[addr]
    static_addrs = {str(r[2]) for r in static_rows}
    taken = {str(r[3]) for r in static_rows} | {c["inner"] for c in clients.values()}
    used = {c["dev"] for c in clients.values()}
    for raw in sorted(set(knocks)):
        try:
            addr = ipaddress.IPv6Address(raw)
        except ValueError:
            continue
        key = str(addr)
        if addr.packed[0] != 0xFD or key in clients or key in static_addrs:
            continue
        inner = str(inner_ipv4(addr))
        if inner in taken:
            notes.append(f"{key}: inner address {inner} is in use by another client")
            continue
        if len(clients) >= max_clients:
            notes.append(f"{key}: the exit is full ({max_clients} open clients)")
            continue
        dev = next(f"fxo{i}" for i in range(max_clients) if f"fxo{i}" not in used)
        used.add(dev)
        taken.add(inner)
        clients[key] = {"dev": dev, "inner": inner, "rx": 0, "seen": now}
        actions.append(("ADD", dev, key, inner))
    return actions, {"clients": clients}, notes


def parse_peer(spec: str):
    m = re.fullmatch(r"\s*(npub1[0-9a-z]+)@([A-Za-z0-9.:\[\]_-]+:\d{1,5})\s*", spec)
    if not m:
        raise ConfigError(f"peer must be npub@host:port: {spec!r}")
    npub_to_pubkey(m.group(1))
    return m.group(1), m.group(2)


def fips_yaml(peer_specs, dns=False):
    """The daemon config. Identity persists in fips.key next to this file;
    the TUN is fips0; fips's own .fips DNS responder is off (the exit runs
    dnsmasq for its clients) unless `dns` asks for it: then it listens on
    loopback only ([::1]:5354, fips's default), for the advert publisher to
    look up a relay on the mesh. Values are validated, then quoted."""
    peers = [parse_peer(s) for s in peer_specs]
    lines = [
        "node:",
        "  identity:",
        "    persistent: true",
        "tun:",
        "  enabled: true",
        "  name: fips0",
        "  mtu: 1280",
        "dns:",
        f"  enabled: {'true' if dns else 'false'}",
        "transports:",
        "  udp:",
        '    bind_addr: "0.0.0.0:2121"',
        "peers:" + ("" if peers else " []"),
    ]
    for npub, addr in peers:
        lines += [
            f'  - npub: "{npub}"',
            "    addresses:",
            "      - transport: udp",
            f'        addr: "{addr}"',
        ]
    return "\n".join(lines) + "\n"


def _split_specs(text):
    return [s for s in re.split(r"[\s,]+", text) if s]


def main(argv):
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    cmd, args = argv[0], argv[1:]
    try:
        if cmd == "addrs":
            for npub in args:
                addr = fips_address(npub)
                print(npub, addr, inner_ipv4(addr))
        elif cmd == "clients":
            for row in clients(parse_allowlist(open(args[0]).read())):
                print(*row)
        elif cmd == "publish":
            for row in parse_publish(args[0] if args else ""):
                print(*row)
        elif cmd == "public-ip":
            log = lambda m: print(f"exitctl: public IP lookup: {m}", file=sys.stderr)  # noqa: E731
            print(*public_ips(parse_lookup(args[0] if args else ""), log=log))
        elif cmd == "nft":
            open_mode, block_tcp = False, list(DEFAULT_OPEN_BLOCK_TCP)
            while args and args[0].startswith("--"):
                flag = args.pop(0)
                if flag == "--open":
                    open_mode = True
                elif flag.startswith("--open-block-tcp="):
                    block_tcp = parse_ports(flag.split("=", 1)[1])
                else:
                    raise ConfigError(f"unknown option: {flag}")
            rows = clients(parse_allowlist(open(args[0]).read()))
            public = [ipaddress.IPv4Address(a) for a in args[3].split()]
            sys.stdout.write(
                nft_ruleset(rows, args[1], args[4:], parse_publish(args[2]), public,
                            open_mode=open_mode, open_block_tcp=block_tcp)
            )
        elif cmd == "open-plan":
            state_file, knock_file, counter_file, clients_file, max_clients, idle = args
            try:
                state = json.loads(open(state_file).read() or "{}")
            except (OSError, ValueError):
                state = {}
            counters = {}
            for line in open(counter_file):
                dev, _, rx = line.partition(" ")
                counters[dev] = int(rx)
            static_rows = [line.split() for line in open(clients_file) if line.strip()]
            actions, new_state, notes = plan_open(
                state, knocked(open(knock_file).read()), counters, int(time.time()),
                static_rows, int(max_clients), int(idle),
            )
            for note in notes:
                print(f"exitctl: open mode: {note}", file=sys.stderr)
            for action in actions:
                print(*action)
            print("STATE", json.dumps(new_state, separators=(",", ":")))
        elif cmd == "nft-public-ip":
            sys.stdout.write(nft_public_ip(args))
        elif cmd == "fips-yaml":
            dns = bool(args) and args[0] == "--dns"
            if dns:
                args = args[1:]
            spec = args[0].strip() if args else ""
            # Empty: the app's default bootstrap servers. "none": no
            # static peers (others dial in, e.g. the e2e test's nodes).
            specs = [] if spec == "none" else _split_specs(spec) if spec else DEFAULT_PEERS
            sys.stdout.write(fips_yaml(specs, dns=dns))
        else:
            print(f"unknown command: {cmd}", file=sys.stderr)
            return 2
    except (ConfigError, ValueError, OSError) as e:
        print(f"exitctl: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
