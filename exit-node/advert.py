#!/usr/bin/env python3
"""fips2go exit node: the exit's advert on Nostr.

An exit that wants to be found says so with one Nostr event, signed with its
own fips key. A fips identity is a Nostr key, so the advert's author IS the
exit: a phone that reads it knows the npub to route to, and nobody else can
advertise that exit. Standard library only, like exitctl.py: the signature
(BIP-340) and the WebSocket client are written out here so the container
needs no further tool, and so both can be tested.

    advert.py check   ACCESS NAME ABOUT RELAY...          validate, print nothing
    advert.py event   KEYFILE ACCESS NAME ABOUT TTL       the signed event (stdout)
    advert.py publish KEYFILE ACCESS NAME ABOUT TTL RELAY...
                                                          sign and send; one line per relay

The event (the contract with the phone, shim/src/exitfind.rs):

    kind     30078  (NIP-78 application data: addressable, one per author)
    tags     ["d", "fips-exit"]
             ["v", "1"]                  the wire contract: IPv4-in-IPv6, next
                                         header 4, inner 100.64.0.0/10 address
             ["access", "open" | "allow-list"]
             ["name", <up to 40 characters>]        optional
             ["about", <up to 200 characters>]      optional
             ["expiration", <unix seconds>]         NIP-40
    content  ""

`access` is what the operator says, not a promise: `open` serves any fips
node, `allow-list` only npubs the operator added (the phone shows its own
npub to send them). The advert expires TTL seconds after it was made and is
published again well before that, so an exit that has gone away drops out of
the lists by itself.

A relay is `wss://host[:port][/path]`, `ws://…`, or one on the mesh:
`ws://<npub>.fips[:port][/path]`. A mesh relay's address is asked of the fips
daemon's own resolver on [::1]:5354 — which is also what tells the daemon
whose address it is, so that it can route there.
"""

import base64
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import sys
import time

# Run with `python3 -I` (isolated: no script directory on the path).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exitctl  # noqa: E402

KIND = 30078
D_TAG = "fips-exit"
VERSION = "1"
ACCESS = ("open", "allow-list")
MAX_NAME = 40
MAX_ABOUT = 200
MAX_RELAYS = 8
TIMEOUT = 10
FIPS_DNS = ("::1", 5354)


class AdvertError(Exception):
    pass


# ---- BIP-340 Schnorr signatures over secp256k1 ----------------------------
# The reference algorithm, as in the BIP. Not constant-time: it signs one
# public event an hour with a key that never leaves this container.

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _tagged(tag: str, msg: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and a[1] != b[1]:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def _mul(point, k: int):
    out = None
    while k:
        if k & 1:
            out = _add(out, point)
        point = _add(point, point)
        k >>= 1
    return out


def _lift_x(x: int):
    if x >= P:
        return None
    c = (pow(x, 3, P) + 7) % P
    y = pow(c, (P + 1) // 4, P)
    if pow(y, 2, P) != c:
        return None
    return x, y if y % 2 == 0 else P - y


def _b(x: int) -> bytes:
    return x.to_bytes(32, "big")


def pubkey(seckey: bytes) -> bytes:
    """The 32-byte x-only public key of a 32-byte secret key."""
    d = int.from_bytes(seckey, "big")
    if not 1 <= d < N:
        raise AdvertError("not a secp256k1 secret key")
    return _b(_mul(G, d)[0])


def sign(msg: bytes, seckey: bytes, aux: bytes) -> bytes:
    """A BIP-340 signature of the 32-byte `msg`."""
    d0 = int.from_bytes(seckey, "big")
    if not 1 <= d0 < N:
        raise AdvertError("not a secp256k1 secret key")
    point = _mul(G, d0)
    d = d0 if point[1] % 2 == 0 else N - d0
    t = _b(d ^ int.from_bytes(_tagged("BIP0340/aux", aux), "big"))
    k0 = int.from_bytes(_tagged("BIP0340/nonce", t + _b(point[0]) + msg), "big") % N
    if k0 == 0:
        raise AdvertError("nonce is zero")
    r = _mul(G, k0)
    k = k0 if r[1] % 2 == 0 else N - k0
    e = int.from_bytes(_tagged("BIP0340/challenge", _b(r[0]) + _b(point[0]) + msg), "big") % N
    sig = _b(r[0]) + _b((k + e * d) % N)
    if not verify(msg, _b(point[0]), sig):
        raise AdvertError("the signature just made does not verify")
    return sig


def verify(msg: bytes, pub: bytes, sig: bytes) -> bool:
    if len(msg) != 32 or len(pub) != 32 or len(sig) != 64:
        return False
    point = _lift_x(int.from_bytes(pub, "big"))
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if point is None or r >= P or s >= N:
        return False
    e = int.from_bytes(_tagged("BIP0340/challenge", sig[:32] + pub + msg), "big") % N
    rr = _add(_mul(G, s), _mul(point, N - e))
    return rr is not None and rr[1] % 2 == 0 and rr[0] == r


# ---- the key file ----------------------------------------------------------


def _bech32_decode(text: str, hrp: str) -> bytes:
    s = text.strip().lower()
    head, sep, data = s.rpartition("1")
    if head != hrp or not sep or any(c not in exitctl.CHARSET for c in data) or len(data) < 7:
        raise AdvertError(f"not an {hrp}")
    values = [exitctl.CHARSET.index(c) for c in data]
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    if exitctl._polymod(expanded + values) != 1:  # noqa: SLF001 — one bech32 for both files
        raise AdvertError(f"{hrp} checksum does not match")
    acc, bits, out = 0, 0, bytearray()
    for v in values[:-6]:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if len(out) != 32:
        raise AdvertError(f"{hrp} is not a 32-byte key")
    return bytes(out)


def read_key(path: str) -> bytes:
    """The secret key in fips's key file (an `nsec1…`, or 64 hex digits)."""
    with open(path) as f:
        text = f.read().strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", text):
        return bytes.fromhex(text)
    return _bech32_decode(text, "nsec")


# ---- the event -------------------------------------------------------------


def clean(text: str, limit: int, what: str) -> str:
    """Operator text for the advert: one line, printable, bounded."""
    text = " ".join(text.split())
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise AdvertError(f"{what} contains control characters")
    if len(text) > limit:
        raise AdvertError(f"{what} is longer than {limit} characters")
    return text


def build_event(seckey: bytes, access: str, name: str, about: str, ttl: int, now=None, aux=None):
    """The signed advert, as a dict ready for `["EVENT", …]`."""
    if access not in ACCESS:
        raise AdvertError(f"access must be one of {', '.join(ACCESS)}")
    if not 300 <= ttl <= 30 * 86400:
        raise AdvertError("the advert's lifetime must be between 5 minutes and 30 days")
    now = int(time.time()) if now is None else now
    tags = [["d", D_TAG], ["v", VERSION], ["access", access]]
    name, about = clean(name, MAX_NAME, "ADVERT_NAME"), clean(about, MAX_ABOUT, "ADVERT_ABOUT")
    if name:
        tags.append(["name", name])
    if about:
        tags.append(["about", about])
    tags.append(["expiration", str(now + ttl)])
    pub = pubkey(seckey).hex()
    body = json.dumps([0, pub, now, KIND, tags, ""], separators=(",", ":"), ensure_ascii=False)
    event_id = hashlib.sha256(body.encode()).digest()
    sig = sign(event_id, seckey, os.urandom(32) if aux is None else aux)
    return {
        "id": event_id.hex(),
        "pubkey": pub,
        "created_at": now,
        "kind": KIND,
        "tags": tags,
        "content": "",
        "sig": sig.hex(),
    }


# ---- relays ----------------------------------------------------------------


def parse_relay(url: str):
    """(tls, host, port, path, npub-or-None) of a relay URL. A `.fips` host
    must be `<npub>.fips`, and is plain `ws`: fips already encrypts."""
    m = re.fullmatch(r"(wss?)://([A-Za-z0-9.-]+)(?::(\d{1,5}))?(/[!-~]*)?", url.strip())
    if not m:
        raise AdvertError(f"not a relay URL (ws:// or wss://): {url!r}")
    tls, host = m.group(1) == "wss", m.group(2).lower()
    port = int(m.group(3) or (443 if tls else 80))
    if not 1 <= port <= 65535:
        raise AdvertError(f"port out of range in {url!r}")
    npub = None
    if host.endswith(".fips"):
        npub = host[: -len(".fips")]
        try:
            exitctl.npub_to_pubkey(npub)
        except exitctl.ConfigError:
            raise AdvertError(f"a relay on the mesh is ws://<npub>.fips: {url!r}") from None
        if tls:
            raise AdvertError(f"a relay on the mesh is ws://, not wss://: {url!r}")
    return tls, host, port, m.group(4) or "/", npub


def parse_relays(text: str):
    urls = exitctl._split_specs(text)  # noqa: SLF001
    if not urls:
        raise AdvertError("ADVERT_RELAYS is empty: name at least one relay to publish to")
    if len(urls) > MAX_RELAYS:
        raise AdvertError(f"ADVERT_RELAYS: at most {MAX_RELAYS} relays")
    for url in urls:
        parse_relay(url)
    return urls


def fips_resolve(npub: str, server=FIPS_DNS, timeout=TIMEOUT) -> str:
    """The mesh address of `npub`, asked of the fips daemon's resolver. The
    answer is known without asking; asking is what registers the identity
    with the daemon, without which it cannot route to the address."""
    name = f"{npub}.fips"
    query = os.urandom(2) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in name.split("."):
        query += bytes([len(label)]) + label.encode()
    query += b"\x00\x00\x1c\x00\x01"  # AAAA, IN
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(query, server)
        reply = s.recv(512)
    finally:
        s.close()
    if len(reply) < 12 or reply[:2] != query[:2] or reply[3] & 15 or reply[7] == 0:
        raise AdvertError(f"the fips daemon does not know {name}")
    return str(exitctl.fips_address(npub))


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise AdvertError("the relay closed the connection")
        buf += chunk
    return buf


def _send_frame(sock, opcode: int, payload: bytes):
    """One masked, unfragmented client frame."""
    head = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([0x80 | n])
    elif n < 65536:
        head += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        head += bytes([0x80 | 127]) + struct.pack(">Q", n)
    mask = os.urandom(4)
    sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))


def _recv_message(sock) -> str:
    """The next text message, answering pings and skipping the rest."""
    while True:
        b0, b1 = _recv_exact(sock, 2)
        n = b1 & 0x7F
        if n == 126:
            (n,) = struct.unpack(">H", _recv_exact(sock, 2))
        elif n == 127:
            (n,) = struct.unpack(">Q", _recv_exact(sock, 8))
        if n > 65536:
            raise AdvertError("the relay sent an oversized frame")
        mask = _recv_exact(sock, 4) if b1 & 0x80 else None
        payload = _recv_exact(sock, n)
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        opcode = b0 & 0x0F
        if opcode == 0x9:
            _send_frame(sock, 0xA, payload)
        elif opcode == 0x8:
            raise AdvertError("the relay closed the connection")
        elif opcode == 0x1 and b0 & 0x80:
            return payload.decode("utf-8", "replace")


def publish(event: dict, url: str, resolve=fips_resolve, timeout=TIMEOUT) -> str:
    """Send `event` to one relay and return what it said ("" = accepted
    with no remark). Raises AdvertError when it was not accepted."""
    tls, host, port, path, npub = parse_relay(url)
    target = resolve(npub) if npub else host
    sock = socket.create_connection((target, port), timeout=timeout)
    try:
        if tls:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        default_port = 443 if tls else 80
        host_header = host if port == default_port else f"{host}:{port}"
        sock.sendall(
            (
                f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\nUser-Agent: fips2go-exit\r\n\r\n"
            ).encode()
        )
        head = b""
        while b"\r\n\r\n" not in head:
            if len(head) > 8192:
                raise AdvertError("the relay's answer is not a WebSocket upgrade")
            head += _recv_exact(sock, 1)
        status = head.split(b"\r\n", 1)[0].decode("latin-1")
        if " 101" not in status:
            raise AdvertError(f"the relay refused the WebSocket: {status}")
        _send_frame(sock, 0x1, json.dumps(["EVENT", event], separators=(",", ":"), ensure_ascii=False).encode())
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                msg = json.loads(_recv_message(sock))
            except ValueError:
                continue
            if isinstance(msg, list) and len(msg) >= 3 and msg[0] == "OK" and msg[1] == event["id"]:
                remark = str(msg[3]) if len(msg) > 3 else ""
                if msg[2] is True:
                    return remark
                raise AdvertError(f"the relay rejected the advert: {remark[:120]}")
        raise AdvertError("the relay did not answer in time")
    finally:
        try:
            sock.close()
        except OSError:
            pass


def main(argv):
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    cmd, args = argv[0], argv[1:]
    try:
        if cmd == "check":
            access, name, about = args[:3]
            if access not in ACCESS:
                raise AdvertError(f"access must be one of {', '.join(ACCESS)}")
            clean(name, MAX_NAME, "ADVERT_NAME")
            clean(about, MAX_ABOUT, "ADVERT_ABOUT")
            parse_relays(" ".join(args[3:]))
        elif cmd == "event":
            keyfile, access, name, about, ttl = args
            print(json.dumps(build_event(read_key(keyfile), access, name, about, int(ttl))))
        elif cmd == "publish":
            keyfile, access, name, about, ttl = args[:5]
            relays = parse_relays(" ".join(args[5:]))
            event = build_event(read_key(keyfile), access, name, about, int(ttl))
            accepted = 0
            for url in relays:
                try:
                    remark = publish(event, url)
                    accepted += 1
                    print(f"{url}: accepted{' (' + remark[:80] + ')' if remark else ''}")
                except (AdvertError, OSError) as e:
                    print(f"{url}: {e}")
            return 0 if accepted else 1
        else:
            print(f"unknown command: {cmd}", file=sys.stderr)
            return 2
    except (AdvertError, exitctl.ConfigError, OSError, ValueError, IndexError) as e:
        print(f"advert: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
