# fips2go exit node

A Docker container that lets **approved** fips2go phones send their mesh apps'
internet traffic out through this machine's connection, like a VPN server.
Phones select it under Overview → *Internet route*. It can also make chosen
services on your LAN, such as a NAS's web page, reachable to those phones over
the mesh, with no port opened on your router ([Publishing
services](#publishing-services)). Nobody else on
the fips mesh can use it.

## Running it

```sh
mkdir -p data
echo "npub1…  my phone" >> data/allowed_npubs             # from the app's Internet route screen
docker compose up -d --build
docker compose logs | grep "exit node up"                 # shows the exit's npub
```

The kernel usually loads `ip6_tunnel` by itself when the container creates its
first tunnel. If the log says `no ip6_tunnel support`, load it on the host:
`sudo modprobe ip6_tunnel`, and add it to `/etc/modules-load.d/` for reboots.

Give the exit's npub to the phone (Internet route → Add an exit node). To
change who is allowed, edit `data/allowed_npubs` and `docker compose restart`
(it is mounted read-only). The exit's identity (`fips.key`) lives in the named
volume `state`, not in `data/`: with every capability dropped, the container's
root cannot write to a host directory owned by your user. Keep the volume
(`docker compose down` keeps it, `down -v` does not), or the exit gets a new
npub and every phone has to be told. Back it up with
`docker compose cp fips-exit:/data/fips.key .`.

Settings are environment variables in `compose.yaml`: `ALLOWED_NPUBS`,
`FIPS_PEERS` (default: the public bootstrap servers the app uses), `WAN_IFACE`,
`BLOCK_CIDRS` (extra destinations clients may never reach), `DNS_UPSTREAMS`,
`PUBLISH` and `PUBLIC_IP_LOOKUP` / `PUBLIC_IP_INTERVAL` (both below).

## This network's public address

The exit blocks its own network's public IPv4 address, as it blocks private
ranges. From inside, that address is your router: a client connecting to it
would reach the router's admin page and, through NAT loopback, every service
you port-forward — the LAN again, by the front door. A web page opened on a
phone knows the address without guessing (it is where the visit comes from),
so it could send the browser there.

Home addresses change, so the exit looks it up rather than taking it as a
setting: at start, before the firewall loads, and then every
`PUBLIC_IP_INTERVAL` seconds (default 300). It asks the services in
`PUBLIC_IP_LOOKUP` (default `https://api.ipify.org https://ipv4.icanhazip.com
https://v4.ident.me`) all at once and blocks **every** public IPv4 address
any of them reports, so a wrong source can only add a block, never lift one.
A private or CGNAT answer is ignored (behind CGNAT the address is the
carrier's, and the problem does not arise).

- **No answer at start:** the exit does not start. Running without the block
  would be silent.
- **No answer later:** the last block stays (the address most likely did not
  change), and the log says so.
- **A change:** the blocked set is swapped in one atomic step, without
  reloading the firewall; open connections to the new address stop at once.
- `PUBLIC_IP_LOOKUP: "off"` turns it off; then put the address in
  `BLOCK_CIDRS` yourself if it never changes.

Those services learn the exit's address and that it checks every few minutes;
they learn nothing about its clients. Two router settings close the same gap
whatever the address: turn off NAT loopback (often "NAT reflection" or
"hairpin NAT"), and do not serve the admin page on the WAN side.

## Publishing services

`PUBLISH` lets the allowed phones reach chosen services on your LAN, or on this
host, through the exit — whether or not they use it as their internet route:

```yaml
      PUBLISH: "8000=192.168.1.20:8000 8080=172.18.0.1:80"   # MESH_PORT=IPv4:PORT
```

On the phone, add the exit's npub to Mesh names (say as `home`), make the app
that opens the service (a browser, say) a mesh app, and use
`http://home.fips:8000`. Each entry is a TCP relay on the exit's fips address:
the service sees connections coming from the container, so its own login still
applies, and plain HTTP is carried inside fips's encryption over the mesh.

- **TCP only**, and the destination is an IPv4 address, not a name.
- **Services on this host**: use the gateway of the container's network
  (`docker compose exec fips-exit ip route` shows it as `default via …`), and
  the service has to listen there, not only on `127.0.0.1`. A host firewall
  (ufw) may have to let the Docker network in.
- Every allowed npub can reach every published port; nobody else on the mesh
  can reach any. There is no per-phone list.
- A relay, not port forwarding: the phones arrive over IPv6 (their fips
  address), the services speak IPv4, and the kernel's NAT does not translate
  between the two. So lock 4 below is unchanged — a client still cannot send
  a single packet to a private address through its tunnel; it can only open a
  TCP connection to the exit's own address on a published port, which the exit
  relays to the one destination configured for it.
- A bad entry stops the exit at start, like a bad npub. Loopback, `0.0.0.0`,
  CGNAT (`100.64/10`, the clients) and multicast cannot be published, nor port
  53 (the exit's DNS).

## Who can use it

Only npubs in the allow-list. That rests on fips itself: a fips address
(`fd…`) is derived from an npub, a session only completes when the peer proves
the key behind the address it claims (fips `core/src/proto/rekey/proof.rs`),
and the receiving node writes the session's address into every packet as its
source — it is not sent on the wire. A packet arriving on `fips0` from an
address therefore came from the holder of that npub's secret key.

On that, the exit puts several independent locks, so one mistake does not open
it:

1. **Allow-list, checked strictly.** Every non-comment line must be a valid
   npub (checksum included); one bad line stops the container rather than
   allowing fewer, or other, clients. No allowed npub: the exit does not start.
2. **Mesh-side firewall, default-deny.** On `fips0` only established traffic,
   IPv4-in-IPv6 and DNS *from allowed addresses*, and a few ICMPv6 types get
   in, plus TCP to the `PUBLISH`ed ports. The exit offers nothing else to the
   mesh.
3. **One tunnel per allowed client.** A Linux `ip6tnl` accepts packets only
   from its own remote, so the tunnels are the allow-list a second time. The
   module's catch-all tunnel `ip6tnl0` is kept down.
4. **Forwarding firewall, default-deny.** A tunnel may forward only packets
   from *its own* client's inner address (no client can pose as another), only
   out of the WAN interface, and never to private, loopback, link-local,
   CGNAT (other clients), multicast or documentation ranges, nor to
   `BLOCK_CIDRS` or the network's own public address (looked up, see
   above). Into a tunnel only replies. No IPv6 forwarding at all, no
   mesh-to-mesh forwarding, NAT only for clients' addresses.
5. **Tunnels reach nothing on the exit itself**, and DNS listens only on the
   exit's fips address.
6. **Fail closed.** The firewall is loaded before fips starts and before any
   tunnel exists; any setup error, or fips or DNS stopping, stops the
   container — and its network namespace with it.
7. **Least privilege.** All capabilities dropped except the five it needs,
   `no-new-privileges`, its own network namespace (not `network_mode: host`).

`e2e-test.sh` checks this for real, with the exit running under exactly the
privileges in `compose.yaml`: an allowed client and an intruder (a fips node
with a working session to the exit but an npub not on the list) on a private
Docker network, plus a web server standing in for the LAN. It asserts that the
client gets internet and DNS but not the LAN server; that the intruder gets no
internet and no DNS, also when it forges the client's inner address; that a
bad or empty allow-list stops the exit before its firewall is even loaded; and
that the catch-all tunnel is down. A fake lookup service reports the
network's public address: the test asserts the client cannot reach it, that a
lookup with no answer stops the exit, and that when the reported address
changes the block moves to the new one while the exit keeps running. With a `PUBLISH` entry pointing at the
web server, it also asserts that the client reaches it on the exit's fips
address while the intruder does not, that an unpublished port stays closed,
and that a bad `PUBLISH` entry stops the exit like a bad npub.

What the operator of an exit can see: everything its clients send to the
internet, as any VPN server can. What it does not get: anything on the phones'
mesh, which never goes through the exit.

## What the phone sends (the contract)

- The selected apps' internet traffic goes to the exit; mesh traffic
  (`fd00::/8`, `.fips` names) never does.
- Each packet is wrapped in an IPv6 packet, plain IP-in-IPv6 with **no tunnel
  header**: source = the phone's fips address, destination = the exit's, hop
  limit 64, **no extension headers**. An IPv4 packet is **next header 4**
  (Linux `ip6tnl` mode `ipip6` with `encaplimit none`). Next header 41 is left
  for IPv6; this version of the app sends none and refuses IPv6 internet
  traffic on the phone with ICMPv6 "administratively prohibited", so apps fall
  back to IPv4 at once. Replies come back the same way.
- The inner IPv4 source is the phone's **inner address**, derived from its
  npub, so nothing is negotiated and two phones never collide in the NAT:

  ```text
  fips address = fd || SHA-256(32-byte x-only pubkey)[0:15]
  inner IPv4   = 100.64.0.0 | ((a[1] << 16 | a[2] << 8 | a[3]) & 0x3fffff)
  ```

  `exitctl.py addrs <npub>…` prints both. The phone's side is
  `shim/src/exit.rs` (`inner_ipv4`); `test_exitctl.py` checks both agree. It
  is also the phone's tunnel address, so the phone rewrites nothing. Two
  allowed npubs with the same inner address (22 bits, so possible but rare) are
  refused at start, with a message naming both.
- `100.64.0.0/10` is not free everywhere: an exit whose own uplink is behind
  carrier-grade NAT (a mobile or satellite connection), or that also runs an
  overlay using the range (Tailscale does), can hold a client's address itself
  and send that client's replies the wrong way. Run the exit elsewhere then.
- **DNS**: while an exit is selected, every non-`.fips` query goes to UDP port
  53 on the exit's fips address, and nowhere else.
- **TCP MSS 1200** for IPv4, on SYNs in both directions, on the phone and in
  the exit's forward chain: planned for a 1280-byte mesh packet, the smallest
  a fips hop carries (1280 − 40 outer IPv6 = 1240 for the inner packet).
- The phone admits only **replies to flows its apps opened** (its own flow
  table: TCP/UDP by ports, ICMP echo by identifier, ICMP errors by the packet
  they quote). The exit cannot open a connection to a phone, whatever its
  firewall says.
- If the exit cannot be reached, the phone **blocks**: nothing goes out through
  its own connection instead.

## Limits

- **Packets over 1240 bytes that are not TCP are lost**, in both directions.
  A Linux `ip6tnl` does not fragment the outer packet, so an inner packet that
  does not fit a 1280-byte mesh packet once wrapped is dropped. TCP is clamped
  to fit; QUIC and other UDP at 1241–1280 bytes are not (QUIC starts at 1200
  bytes, and implementations that probe for a larger size fall back). The
  container is meant to move to `fips-exit`'s daemon, which fragments the
  outer packet (RFC 2473 §7.1), once that is public.
- **A fragmented reply never arrives.** The phone reads the ports of a
  reply to match it to a flow an app opened, and only the first fragment
  carries them, so later fragments are dropped. In practice this is the same
  limit: a reply the exit had to fragment was over 1240 bytes.

## Files

| File | |
|---|---|
| `compose.yaml` | How to run it: capabilities, sysctls, settings |
| `Dockerfile` | fips daemon built from the fork rev the app pins (`FIPS_REV`; CI keeps it in sync) |
| `entrypoint.sh` | Start-up in fail-closed order, then supervises fips, DNS, the `PUBLISH` relays and the public-address watch |
| `exitctl.py` | Allow-list, `PUBLISH` entries, addresses, public-address lookup, firewall ruleset, fips config — prints, so it is testable |
| `test_exitctl.py` | Unit tests: `python3 -I -m unittest discover -s exit-node` (also run in CI) |
| `e2e-test.sh` | The allowed-client / intruder test on Docker |

## Checking a running exit

```sh
docker compose exec fips-exit nft list table inet fips_exit   # the firewall
docker compose exec fips-exit ip -d link show type ip6tnl     # one fxN per client
docker compose exec fips-exit fipsctl show sessions           # who is connected
docker compose exec fips-exit nft list set inet fips_exit blocked_dyn  # the public address blocked now
docker compose logs | grep -E "publishing|public address"     # published services, address changes
```

## Troubleshooting

- **`WAN interface eth0, does not exist`** (or any value with a stray `,` or
  quote): in `compose.yaml`'s `KEY: value` form everything after the colon is
  the value, a trailing comma included. Lists in `PUBLISH`, `BLOCK_CIDRS` and
  the like are separated by spaces inside one quoted string.
- **`cannot find this network's public IPv4 address`**: no lookup service
  answered at start. Check that the host has internet access; if outbound
  HTTPS to those services is blocked, list your own in `PUBLIC_IP_LOOKUP`, or
  set it to `off` and put the address in `BLOCK_CIDRS`.
- **A published service does not answer:** the log line `publishing … ->
  HOST:PORT` shows where the relay connects; test that from the host
  (`curl HOST:PORT`). A service in another container on this host is reached
  by the host's LAN address or the Docker bridge gateway, not `127.0.0.1`
  (which is the exit container itself).
