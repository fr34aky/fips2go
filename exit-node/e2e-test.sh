#!/bin/bash
# End-to-end test of the exit node's allow-list, on Docker.
#
# Three fips nodes on a private Docker network: the exit (allowing one npub),
# an allowed client, and an intruder whose npub is not on the list. Each
# client side is the Linux equivalent of what the phone does (an ip6tnl
# ipip6 tunnel from its fips address to the exit's, its inner address on
# it). Asserts:
#   - the allowed client reaches the internet and DNS through the exit;
#   - the intruder, with a working fips session to the exit, gets neither —
#     not with its own inner address, and not with the client's;
#   - the client cannot reach private addresses through the exit;
#   - a service published with PUBLISH is reachable on the exit's fips
#     address by the client only, and an unpublished port is not;
#   - the exit network's own public address is blocked, and the block follows
#     it when it changes (a fake lookup service stands in for the real ones).
#
# Needs: docker with compose, internet access, and ip6_tunnel on the host
# (sudo modprobe ip6_tunnel). Build first: docker build -t fips2go-exit:dev .
set -euo pipefail
cd "$(dirname "$0")"

IMG=${IMG:-fips2go-exit:dev}
NET=fips-exit-e2e
P=e2e-fips-exit
pass=0 fail=0

ok() { echo "PASS  $*"; pass=$((pass + 1)); }
bad() { echo "FAIL  $*"; fail=$((fail + 1)); }
cleanup() {
  docker rm -f "$P-exit" "$P-client" "$P-intruder" "$P-lan" "$P-ipsrc" > /dev/null 2>&1 || true
  docker volume rm "$P-exit" "$P-client" "$P-intruder" > /dev/null 2>&1 || true
  docker network rm "$NET" > /dev/null 2>&1 || true
  if [ -n "${WORK:-}" ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
cleanup
docker network create "$NET" > /dev/null

npub_of() {
  docker volume create "$P-$1" > /dev/null
  docker run --rm -v "$P-$1:/data" --entrypoint fipsctl "$IMG" keygen -d /data > /dev/null 2>&1
  docker run --rm -v "$P-$1:/data" --entrypoint cat "$IMG" /data/fips.pub | tr -d '[:space:]'
}
CLIENT=$(npub_of client)
INTRUDER=$(npub_of intruder)
EXIT=$(npub_of exit)
echo "exit $EXIT"
echo "client $CLIENT (allowed)"
echo "intruder $INTRUDER (not allowed)"

# A web server on the exit's private network: stands for the LAN and the
# host, which clients must never reach through the exit —
# except as the service the exit publishes (PUBLISH).
docker run -d --name "$P-lan" --network "$NET" --entrypoint python3 "$IMG" \
  -I -m http.server 8080 > /dev/null
LAN_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$P-lan")

# A public-IP lookup service whose answer the test changes: it first says
# the exit's network is at 1.0.0.1 (a real address, so blocking it is
# observable), later 1.1.1.1.
docker run -d --name "$P-ipsrc" --network "$NET" --entrypoint bash "$IMG" \
  -c 'mkdir -p /srv && echo 1.0.0.1 > /srv/ip && exec python3 -I -m http.server 8081 --directory /srv' \
  > /dev/null
IPSRC=http://$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$P-ipsrc"):8081/ip

# The exit runs from compose.yaml itself, so the test covers what is deployed
# (privileges, sysctls, mounts) rather than a copy of it. The override only
# joins it to the test network, uses the prepared identity and peers nowhere.
# The allow-list is a file owned by the user running the test, as on a real
# host: the container's root, with every capability dropped, can read it but
# could not write or chmod it.
WORK=$(mktemp -d)
cp compose.yaml "$WORK/"
mkdir "$WORK/data"
printf '# e2e\n%s  client\n' "$CLIENT" > "$WORK/data/allowed_npubs"
cat > "$WORK/override.yaml" << EOF
services:
  fips-exit:
    image: $IMG
    pull_policy: never
    container_name: $P-exit
    restart: "no"
    environment:
      FIPS_PEERS: none
      PUBLISH: "8000=$LAN_IP:8080"
      PUBLIC_IP_LOOKUP: "$IPSRC"
      PUBLIC_IP_INTERVAL: "5"
      RUST_LOG: warn
networks:
  default:
    external: true
    name: $NET
volumes:
  state:
    external: true
    name: $P-exit
EOF
docker compose -p "$P" --project-directory "$WORK" \
  -f "$WORK/compose.yaml" -f "$WORK/override.yaml" up -d --no-build > /dev/null
for _ in $(seq 90); do
  docker logs "$P-exit" 2>&1 | grep -q "exit node up" && break
  docker ps -q -f name="$P-exit" | grep -q . || break
  sleep 1
done
if ! docker logs "$P-exit" 2>&1 | grep -q "exit node up"; then
  docker logs "$P-exit" 2>&1 | tail -30
  echo "FAIL  exit did not come up"
  exit 1
fi
EXIT_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$P-exit")

# A client node: fips peered with the exit, plus the phone's side of the
# tunnel. Routes only the test destinations through it.
start_node() {
  docker run -d --name "$P-$1" --network "$NET" \
    --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    -e EXIT_NPUB="$EXIT" -e EXIT_IP="$EXIT_IP" -e LAN_IP="$LAN_IP" -e RUST_LOG=warn \
    -v "$P-$1:/data" --entrypoint bash "$IMG" -c '
set -eu
cat > /data/fips.yaml <<EOF
node:
  identity:
    persistent: true
tun:
  enabled: true
  name: fips0
  mtu: 1280
dns:
  enabled: false
transports:
  udp:
    bind_addr: "0.0.0.0:2121"
peers:
  - npub: "$EXIT_NPUB"
    addresses:
      - transport: udp
        addr: "$EXIT_IP:2121"
EOF
fips -c /data/fips.yaml &
for _ in $(seq 60); do
  ME=$(ip -6 -o addr show dev fips0 scope global 2>/dev/null | awk "{print \$4}" | cut -d/ -f1 | head -1)
  [ -n "$ME" ] && break; sleep 1
done
EXIT_FD=$(fipsctl address "$EXIT_NPUB")
INNER=$(python3 -I /opt/exit/exitctl.py addrs "$(cat /data/fips.pub)" | awk "{print \$3}")
ip -6 tunnel add t0 mode ipip6 local "$ME" remote "$EXIT_FD" encaplimit none hoplimit 64
ip addr add "$INNER/32" dev t0
ip link set t0 mtu 1200 up
ip route add 1.1.1.1/32 dev t0 src "$INNER"
ip route add 1.0.0.1/32 dev t0 src "$INNER"
ip route add "$LAN_IP/32" dev t0 src "$INNER"
echo "$EXIT_FD" > /tmp/exit_fd; echo "$INNER" > /tmp/inner; echo "$ME" > /tmp/me; echo ready > /tmp/ready
wait' > /dev/null
}
start_node client
start_node intruder
for n in client intruder; do
  for _ in $(seq 60); do
    docker exec "$P-$n" test -f /tmp/ready 2> /dev/null && break
    sleep 1
  done
  docker exec "$P-$n" test -f /tmp/ready || { docker logs "$P-$n" | tail -20; echo "FAIL  $n did not start"; exit 1; }
done

# tcp NODE ADDR PORT SECONDS SRC -> ok | refused | timeout (retries until ok)
tcp() {
  docker exec "$P-$1" python3 -I -c '
import socket, sys, time
host, port, secs, src = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
end, last = time.time() + secs, "timeout"
while time.time() < end:
    s = socket.socket(); s.settimeout(3)
    try:
        s.bind((src, 0)); s.connect((host, port)); print("ok"); sys.exit()
    except ConnectionRefusedError: last = "refused"
    except OSError: last = "timeout"
    finally: s.close()
    time.sleep(1)
print(last)' "$2" "$3" "$4" "$5"
}
# dns NODE SECONDS -> ok | none (an A answer for example.com from the exit)
dns() {
  docker exec "$P-$1" python3 -I -c '
import socket, sys, time
server, secs = open("/tmp/exit_fd").read().strip(), float(sys.argv[1])
q = bytes.fromhex("abcd01000001000000000000076578616d706c6503636f6d0000010001")
end = time.time() + secs
while time.time() < end:
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.settimeout(3)
    try:
        s.sendto(q, (server, 53)); r = s.recv(512)
        if r[:2] == q[:2] and r[3] & 15 == 0 and int.from_bytes(r[6:8], "big") > 0:
            print("ok"); sys.exit()
    except OSError: pass
    finally: s.close()
    time.sleep(1)
print("none")' "$2"
}
inner() { docker exec "$P-$1" cat /tmp/inner; }
# http6 NODE PORT SECONDS -> ok | refused | timeout | <other> (an HTTP GET to
# the exit's fips address from the node's own, over the mesh; retries until ok)
http6() {
  docker exec "$P-$1" python3 -I -c '
import socket, sys, time
port, secs = int(sys.argv[1]), float(sys.argv[2])
exit_fd, me = open("/tmp/exit_fd").read().strip(), open("/tmp/me").read().strip()
end, last = time.time() + secs, "timeout"
while time.time() < end:
    s = socket.socket(socket.AF_INET6); s.settimeout(3)
    try:
        s.bind((me, 0)); s.connect((exit_fd, port))
        s.sendall(b"GET / HTTP/1.0\r\n\r\n"); r = s.recv(64)
        if r.startswith(b"HTTP/1.0 200"): print("ok"); sys.exit()
        last = repr(r[:20])
    except ConnectionRefusedError: last = "refused"
    except OSError: last = "timeout"
    finally: s.close()
    time.sleep(1)
print(last)' "$2" "$3"
}

echo "--- allowed client"
r=$(tcp client 1.1.1.1 80 45 "$(inner client)")
[ "$r" = ok ] && ok "client reaches the internet through the exit" || bad "client internet: $r"
r=$(tcp client 1.0.0.1 80 10 "$(inner client)")
[ "$r" = timeout ] && ok "client cannot reach the exit network's public address (1.0.0.1)" ||
  bad "CLIENT REACHED THE EXIT NETWORK'S PUBLIC ADDRESS: $r"
r=$(dns client 30)
[ "$r" = ok ] && ok "client resolves names with the exit's DNS" || bad "client DNS: $r"

# The LAN server answers the exit directly (so it is up), but must not
# answer the client through the exit.
ctl=$(docker exec "$P-exit" python3 -I -c '
import socket
s = socket.socket(); s.settimeout(3)
try: s.connect(("'"$LAN_IP"'", 8080)); print("ok")
except OSError as e: print(e)')
if [ "$ctl" != ok ]; then
  bad "test setup: the LAN server does not answer the exit directly ($ctl)"
else
  r=$(tcp client "$LAN_IP" 8080 10 "$(inner client)")
  [ "$r" = timeout ] && ok "client cannot reach a private address ($LAN_IP) through the exit" ||
    bad "CLIENT REACHED A PRIVATE ADDRESS ($LAN_IP) THROUGH THE EXIT: $r"
fi

r=$(http6 client 8000 30)
[ "$r" = ok ] && ok "client reaches the published service (exit :8000 -> $LAN_IP:8080)" ||
  bad "client published service: $r"
r=$(http6 client 8001 8)
[ "$r" = timeout ] && ok "client cannot reach an unpublished port on the exit" ||
  bad "CLIENT REACHED AN UNPUBLISHED PORT ON THE EXIT: $r"

echo "--- intruder (not on the allow-list)"
r=$(tcp intruder 1.1.1.1 80 25 "$(inner intruder)")
[ "$r" = timeout ] && ok "intruder gets no internet" || bad "INTRUDER REACHED THE INTERNET: $r"
r=$(dns intruder 10)
[ "$r" = none ] && ok "intruder gets no DNS" || bad "INTRUDER GOT DNS"
r=$(http6 intruder 8000 10)
[ "$r" = timeout ] && ok "intruder cannot reach the published service" ||
  bad "INTRUDER REACHED THE PUBLISHED SERVICE: $r"
# The intruder does reach the exit over fips: the block is the allow-list,
# not a broken mesh.
if docker exec "$P-intruder" fipsctl show sessions 2> /dev/null | grep -qi established; then
  ok "intruder has an established fips session to the exit (so the firewall is what stops it)"
else
  bad "intruder has no fips session to the exit; the checks above prove nothing"
fi
# Spoofing the allowed client's inner address does not help.
docker exec "$P-intruder" sh -c "ip addr add $(inner client)/32 dev t0"
r=$(tcp intruder 1.1.1.1 80 15 "$(inner client)")
[ "$r" = timeout ] && ok "intruder spoofing the client's inner address gets no internet" ||
  bad "INTRUDER REACHED THE INTERNET WITH A SPOOFED ADDRESS: $r"

echo "--- exit"
# Fail closed: a bad or empty allow-list stops the exit before anything runs.
# So does a bad PUBLISH entry, and a public-IP lookup that gets no answer.
for c in "$CLIENT npub1typo||" "||" "$CLIENT|8000=127.0.0.1:8000|" "$CLIENT|8000=nas.local:80|" \
  "$CLIENT||http://127.0.0.1:9/ip" "$CLIENT||ftp://example.org/ip"; do
  IFS='|' read -r list pub lookup <<< "$c"
  out=$(docker run --rm --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 -e ALLOWED_NPUBS="$list" -e PUBLISH="$pub" \
    -e PUBLIC_IP_LOOKUP="$lookup" "$IMG" 2>&1) && rc=0 || rc=$?
  what="allow-list '${list:-<empty>}', PUBLISH '${pub:-<empty>}', PUBLIC_IP_LOOKUP '${lookup:-<default>}'"
  if [ "$rc" != 0 ] && echo "$out" | grep -q FATAL && ! echo "$out" | grep -q "firewall loaded"; then
    ok "refuses to start with $what"
  else
    bad "started with $what (rc $rc)"
  fi
done
# No allow-list file: compose refuses, and leaves no root-owned directory
# where the file should be (which the operator could not remove).
mkdir -p "$WORK/empty/data"
cp compose.yaml "$WORK/empty/"
printf 'services:\n  fips-exit:\n    image: %s\n    pull_policy: never\n' "$IMG" \
  > "$WORK/empty/override.yaml"
empty() {
  docker compose -p "$P-empty" --project-directory "$WORK/empty" \
    -f "$WORK/empty/compose.yaml" -f "$WORK/empty/override.yaml" "$@"
}
out=$(empty up -d --no-build 2>&1) && rc=0 || rc=$?
empty down -v > /dev/null 2>&1 || true
if [ "$rc" = 0 ]; then
  bad "compose started the exit with no data/allowed_npubs"
elif [ -e "$WORK/empty/data/allowed_npubs" ]; then
  bad "compose created data/allowed_npubs on the host"
elif ! echo "$out" | grep -q allowed_npubs; then
  bad "compose failed with no data/allowed_npubs, but not because of it: $out"
else
  ok "compose refuses to start with no data/allowed_npubs"
fi
docker exec "$P-exit" sh -c 'ip -d link show ip6tnl0 2>/dev/null | grep -q "state DOWN"' &&
  ok "catch-all tunnel ip6tnl0 is down" || bad "ip6tnl0 is not down"

# The public address changes while the exit runs: the block follows it.
# Last, since it blocks 1.1.1.1, which the checks above use.
docker exec "$P-ipsrc" sh -c 'echo 1.1.1.1 > /srv/ip.new && mv /srv/ip.new /srv/ip'
for _ in $(seq 30); do
  docker logs "$P-exit" 2>&1 | grep -q "public address changed: blocking 1.1.1.1" && break
  sleep 1
done
if ! docker logs "$P-exit" 2>&1 | grep -q "public address changed: blocking 1.1.1.1"; then
  bad "the exit did not pick up the changed public address"
else
  r=$(tcp client 1.0.0.1 80 30 "$(inner client)")
  [ "$r" = ok ] && ok "the old public address is reachable again after the change" ||
    bad "old public address after the change: $r"
  r=$(tcp client 1.1.1.1 80 10 "$(inner client)")
  [ "$r" = timeout ] && ok "the new public address is blocked after the change" ||
    bad "CLIENT REACHED THE NEW PUBLIC ADDRESS: $r"
fi
docker ps -q -f name="$P-exit" | grep -q . && ok "the exit kept running through the change" ||
  bad "the exit stopped during the change"

echo "passed $pass, failed $fail"
[ "$fail" = 0 ]
