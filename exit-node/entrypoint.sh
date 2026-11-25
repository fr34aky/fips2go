#!/bin/bash
# fips2go exit node. Fail-closed order: allow-list checked, firewall loaded
# (default-deny), and only then fips, the per-client tunnels and DNS. Any
# failure stops the container — and with it the network namespace, so no
# half-configured exit is ever left forwarding. See README.md.
set -euo pipefail

DATA=/data
# Bind-mounted read-only from the host (compose.yaml), so the operator edits
# it without root; /data is a named volume the container owns.
ALLOWED_FILE=/etc/exit/allowed_npubs
RUN=/run/exit
CTL="python3 -I /opt/exit/exitctl.py"
WAN=${WAN_IFACE:-eth0}
DNS_UPSTREAMS=${DNS_UPSTREAMS:-1.1.1.1 9.9.9.9}
PUBLIC_IP_LOOKUP=${PUBLIC_IP_LOOKUP:-}
PUBLIC_IP_INTERVAL=${PUBLIC_IP_INTERVAL:-300}
# Open mode: serve any fips node, not only the allow-list. See README.md.
OPEN=${OPEN:-0}
OPEN_MAX_CLIENTS=${OPEN_MAX_CLIENTS:-64}
OPEN_IDLE_SECS=${OPEN_IDLE_SECS:-600}
OPEN_BLOCK_TCP_PORTS=${OPEN_BLOCK_TCP_PORTS-25}

log() { echo "exit-node: $*" >&2; }
die() { log "FATAL: $*"; exit 1; }
# Any command failing under set -e ends the container: say where.
trap 'log "FATAL: line $LINENO: $BASH_COMMAND failed"' ERR
fips0_addr() {
  { ip -6 -o addr show dev fips0 scope global 2> /dev/null || true; } |
    awk '{print $4}' | cut -d/ -f1 | head -1
}

mkdir -p "$RUN"
chmod 700 "$DATA"

# 1. Allow-list: $ALLOWED_FILE, plus ALLOWED_NPUBS from the environment.
#    One bad entry stops the exit (exitctl refuses it).
: > "$RUN/allowed"
# A missing bind-mount source makes Docker create a directory there.
[ -d "$ALLOWED_FILE" ] &&
  die "$ALLOWED_FILE is a directory: create data/allowed_npubs before the first start"
[ -f "$ALLOWED_FILE" ] && cat "$ALLOWED_FILE" >> "$RUN/allowed"
printf '%s\n' ${ALLOWED_NPUBS:-} >> "$RUN/allowed"
$CTL clients "$RUN/allowed" > "$RUN/clients" || die "the allow-list is invalid (see above)"
case "$OPEN" in
  0 | 1) ;;
  *) die "OPEN must be 0 or 1" ;;
esac
if [ "$OPEN" = 1 ]; then
  [[ "$OPEN_MAX_CLIENTS" =~ ^[0-9]+$ ]] && [ "$OPEN_MAX_CLIENTS" -ge 1 ] && [ "$OPEN_MAX_CLIENTS" -le 1024 ] ||
    die "OPEN_MAX_CLIENTS must be a number from 1 to 1024"
  [[ "$OPEN_IDLE_SECS" =~ ^[0-9]+$ ]] && [ "$OPEN_IDLE_SECS" -ge 30 ] ||
    die "OPEN_IDLE_SECS must be a number of seconds, at least 30"
  log "OPEN MODE: any fips node may use this exit for internet access (up to $OPEN_MAX_CLIENTS at once)"
else
  [ -s "$RUN/clients" ] ||
    die "no allowed npubs: list them in data/allowed_npubs (one per line) or ALLOWED_NPUBS (or set OPEN=1 to serve anyone)"
fi

# Services published to the clients (PUBLISH): checked here, before the
# firewall, so a bad entry stops the exit like a bad npub does.
$CTL publish "${PUBLISH:-}" > "$RUN/publish" || die "PUBLISH is invalid (see above)"

# This network's own public IPv4 address, blocked like a private range: from
# inside, it reaches the router (its admin page) and, through NAT loopback,
# every port-forwarded LAN service. Looked up before the firewall loads; no
# answer stops the exit, since running without the block would be silent.
[[ "$PUBLIC_IP_INTERVAL" =~ ^[0-9]+$ ]] && [ "$PUBLIC_IP_INTERVAL" -ge 5 ] ||
  die "PUBLIC_IP_INTERVAL must be a number of seconds, at least 5"
PUBLIC_IPS=$($CTL public-ip "$PUBLIC_IP_LOOKUP") ||
  die "cannot find this network's public IPv4 address (see above); set PUBLIC_IP_LOOKUP=off to run without blocking it"
if [ "$PUBLIC_IP_LOOKUP" = off ]; then
  log "public IP lookup off: this network's public address is not blocked (unless in BLOCK_CIDRS)"
else
  log "blocking this network's public address: $PUBLIC_IPS"
fi

# 2. Kernel settings the firewall relies on.
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] ||
  die "net.ipv4.ip_forward must be 1 (compose: sysctls)"
[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" = 0 ] ||
  die "net.ipv6.conf.all.forwarding must be 0: this exit only forwards IPv4"
ip link show "$WAN" > /dev/null 2>&1 || die "WAN interface $WAN does not exist (WAN_IFACE)"

# 3. Firewall first: default-deny forwarding, mesh input only from allowed
#    clients. Loaded atomically; nothing below runs if it does not load.
NFT_OPTS=()
[ "$OPEN" = 1 ] && NFT_OPTS=(--open "--open-block-tcp=$OPEN_BLOCK_TCP_PORTS")
# shellcheck disable=SC2086
$CTL nft "${NFT_OPTS[@]}" "$RUN/allowed" "$WAN" "${PUBLISH:-}" "$PUBLIC_IPS" ${BLOCK_CIDRS:-} > "$RUN/rules.nft" || die "cannot build the firewall"
nft -f "$RUN/rules.nft" || die "cannot load the firewall"
log "firewall loaded"

# 4. IPv4-in-IPv6 tunnels need ip6_tunnel, which a container cannot load.
if ! ip -6 tunnel add fxprobe mode ipip6 local ::1 remote ::2 encaplimit none 2> /dev/null; then
  die "no ip6_tunnel support: run 'modprobe ip6_tunnel' on the host (and add it to /etc/modules-load.d)"
fi
ip -6 tunnel del fxprobe
# The module's catch-all tunnel takes packets no listed tunnel matches.
# It must never be up: that would accept every client.
ip link set ip6tnl0 down 2> /dev/null || true

# 5. fips, with a persistent identity in /data.
$CTL fips-yaml "${FIPS_PEERS:-}" > "$DATA/fips.yaml" || die "invalid FIPS_PEERS"
fips -c "$DATA/fips.yaml" &
FIPS_PID=$!
EXIT_FD=""
for _ in $(seq 60); do
  kill -0 "$FIPS_PID" 2> /dev/null || die "fips exited during start"
  EXIT_FD=$(fips0_addr)
  [ -n "$EXIT_FD" ] && break
  sleep 1
done
[ -n "$EXIT_FD" ] || die "fips0 did not come up"
FIPS_MTU=$(cat /sys/class/net/fips0/mtu)
ip link set ip6tnl0 down 2> /dev/null || true

# 6. One tunnel per allowed client. A tunnel accepts packets only from its
#    own remote, so this list is the allow-list a second time.
#    encaplimit none: Linux otherwise adds a destination-options header,
#    which the phone does not accept.
while read -r dev npub client_fd inner; do
  ip -6 tunnel add "$dev" mode ipip6 local "$EXIT_FD" remote "$client_fd" \
    encaplimit none hoplimit 64
  ip link set "$dev" mtu $((FIPS_MTU - 40)) up
  ip route replace "$inner/32" dev "$dev"
  log "allowed $npub (inner $inner, $dev)"
done < "$RUN/clients"
ip link set ip6tnl0 down 2> /dev/null || true

# 6b. Open mode: admit whoever knocks. The firewall notes the address of a
#     first packet (set knock6); this loop builds that client's tunnel and
#     only then lets its traffic in (set open6), and removes clients that
#     have gone quiet. exitctl decides; this only carries it out. Order
#     matters both ways: the tunnel exists before the firewall accepts for
#     it, and the firewall stops accepting before the tunnel goes.
open_loop() {
  local verb dev addr inner tick=0
  echo '{}' > "$RUN/open.state"
  # A reply for a client that has been removed must not find the default
  # route (the /32 of a live client is more specific than this).
  ip route replace blackhole 100.64.0.0/10
  while sleep 2; do
    nft -j list set inet fips_exit knock6 > "$RUN/knock.json" 2> /dev/null || continue
    tick=$((tick + 1))
    # Nobody knocking: only look again every 30 s, for clients gone idle.
    grep -q '"elem"' "$RUN/knock.json" || [ $((tick % 15)) = 0 ] || continue
    : > "$RUN/open.counters"
    for d in /sys/class/net/fxo*; do
      [ -e "$d" ] && echo "${d##*/} $(cat "$d/statistics/rx_packets")" >> "$RUN/open.counters"
    done
    $CTL open-plan "$RUN/open.state" "$RUN/knock.json" "$RUN/open.counters" \
      "$RUN/clients" "$OPEN_MAX_CLIENTS" "$OPEN_IDLE_SECS" > "$RUN/open.plan" || continue
    while read -r verb dev addr inner; do
      case "$verb" in
        ADD)
          ip -6 tunnel del "$dev" 2> /dev/null || true
          if ip -6 tunnel add "$dev" mode ipip6 local "$EXIT_FD" remote "$addr" encaplimit none hoplimit 64 &&
            ip link set "$dev" mtu $((FIPS_MTU - 40)) up &&
            ip route replace "$inner/32" dev "$dev" &&
            nft "add element inet fips_exit client_src { \"$dev\" . $inner }; add element inet fips_exit clients4 { $inner }; add element inet fips_exit open6 { $addr }"; then
            ip link set ip6tnl0 down 2> /dev/null || true
            log "open: admitted $addr (inner $inner, $dev)"
          else
            log "open: could not admit $addr; it is not served"
            nft "delete element inet fips_exit open6 { $addr }" 2> /dev/null || true
            ip -6 tunnel del "$dev" 2> /dev/null || true
          fi
          ;;
        DEL)
          nft "delete element inet fips_exit open6 { $addr }" 2> /dev/null || true
          nft "delete element inet fips_exit clients4 { $inner }" 2> /dev/null || true
          nft "delete element inet fips_exit client_src { \"$dev\" . $inner }" 2> /dev/null || true
          ip route del "$inner/32" dev "$dev" 2> /dev/null || true
          ip -6 tunnel del "$dev" 2> /dev/null || true
          log "open: dropped $addr (idle)"
          ;;
        STATE) echo "$dev" > "$RUN/open.state" ;;
      esac
    done < "$RUN/open.plan"
  done
}

# 7. DNS for the clients, on the exit's fips address only (the firewall
#    lets only allowed clients reach it).
servers=()
for s in $DNS_UPSTREAMS; do servers+=("--server=$s"); done
dnsmasq --keep-in-foreground --no-resolv --no-hosts --bind-dynamic \
  --listen-address="$EXIT_FD" --except-interface=lo \
  --domain-needed --bogus-priv --stop-dns-rebind --cache-size=1000 \
  "${servers[@]}" &
DNS_PID=$!

# 8. Published services: a TCP relay per entry, listening on the exit's
#    fips address only (the firewall lets only allowed clients reach it) and
#    connecting to the configured host. A relay, not DNAT: clients arrive
#    over IPv6, the services speak IPv4, and the kernel's NAT does not
#    translate between the two. It also keeps the forward chain's block on
#    private ranges as it is. socat drops to nobody after binding.
PIDS=("$FIPS_PID" "$DNS_PID")
while read -r mesh_port host port; do
  socat -d "TCP6-LISTEN:$mesh_port,bind=[$EXIT_FD],reuseaddr,fork,max-children=64,su=nobody" \
    "TCP4:$host:$port,connect-timeout=10" &
  PIDS+=($!)
  log "publishing [$EXIT_FD]:$mesh_port -> $host:$port"
done < "$RUN/publish"

# 9. Keep the public-address block current: the address can change while
#    the exit runs. A failed lookup keeps the last block (the address most
#    likely did not change); a block that cannot be updated stops the exit.
watch_public_ip() {
  local current=$PUBLIC_IPS new
  while sleep "$PUBLIC_IP_INTERVAL"; do
    # One source failing is not news every few minutes: its error is shown
    # only when no source answers.
    if ! new=$($CTL public-ip "$PUBLIC_IP_LOOKUP" 2> "$RUN/lookup.err"); then
      cat "$RUN/lookup.err" >&2
      log "public IP lookup failed; still blocking $current"
      continue
    fi
    [ "$new" = "$current" ] && continue
    # shellcheck disable=SC2086
    if ! $CTL nft-public-ip $new | nft -f -; then
      log "FATAL: cannot update the public-address block to $new"
      return 1
    fi
    log "public address changed: blocking $new (was $current)"
    current=$new
  done
}
if [ "$PUBLIC_IP_LOOKUP" != off ]; then
  watch_public_ip &
  PIDS+=($!)
fi
if [ "$OPEN" = 1 ]; then
  open_loop &
  PIDS+=($!)
fi

log "exit node up: $(cat "$DATA/fips.pub" 2> /dev/null || echo '?') at $EXIT_FD, $(wc -l < "$RUN/clients") client(s)"

# 10. Supervise: if fips, DNS, a relay or the public-address watch stops,
#     the container stops.
trap 'kill "${PIDS[@]}" 2> /dev/null || true' TERM INT
trap - ERR
set +e
wait -n "${PIDS[@]}"
status=$?
kill "${PIDS[@]}" 2> /dev/null
wait
log "stopped (status $status)"
exit "$status"
