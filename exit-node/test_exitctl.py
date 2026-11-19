"""Tests for exitctl.py:  python3 -I -m unittest discover -s exit-node

The firewall itself is exercised in a real container by `selftest.sh`;
these pin down what it is generated from.
"""

import ipaddress
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exitctl as x  # noqa: E402

# Vectors printed by the phone's own code
# (cargo test exit::tests::print_vector -- --ignored --nocapture).
VECTORS = [
    ("npub1egc9jnrzerzy9hvmkremut4cyq05nqrp8ta9s9c9rkf8ak4c08fq6vj2y4",
     "fd78:56c9:7bcd:d690:d024:a45f:3fdc:e14c", "100.120.86.201"),
    ("npub1g8m2y2s8v4uaksff0w4wqle5n8vwrxzjsyj5t9sfrau8par73upshx64mh",
     "fdf1:5704:54a4:8240:e6bc:df72:56d2:39e7", "100.113.87.4"),
    ("npub1sa27mk55q32ayly03vnh333n2n4qa0g4866u7uxg8vl423k8dtdsghghq2",
     "fd96:74a1:b794:6dba:39dc:e316:c82:f7ba", "100.86.116.161"),
]
A, B, C = (v[0] for v in VECTORS)


class Addresses(unittest.TestCase):
    def test_matches_the_phone(self):
        for npub, addr, inner in VECTORS:
            a = x.fips_address(npub)
            self.assertEqual(a, ipaddress.IPv6Address(addr))
            self.assertEqual(x.inner_ipv4(a), ipaddress.IPv4Address(inner))

    def test_rejects_typos_and_other_keys(self):
        bad = [
            A[:-1] + ("q" if A[-1] != "q" else "p"),  # checksum
            A.replace("npub", "nsec"),  # a secret key, or another type
            "npub1",
            "",
            A[:20],
            A[:10] + A[10:].upper(),  # mixed case
        ]
        for npub in bad:
            with self.assertRaises(x.ConfigError, msg=npub):
                x.npub_to_pubkey(npub)

    def test_uppercase_is_the_same_npub(self):
        self.assertEqual(x.fips_address(A.upper()), x.fips_address(A))


class Allowlist(unittest.TestCase):
    def test_comments_labels_and_duplicates(self):
        text = f"# phones\n{A}  my pixel\n\n{B} # tablet\n{A.upper()}\n"
        self.assertEqual(x.parse_allowlist(text), [A, B])

    def test_one_bad_line_stops_everything(self):
        with self.assertRaises(x.ConfigError) as e:
            x.parse_allowlist(f"{A}\nnpub1typo\n{B}\n")
        self.assertIn("line 2", str(e.exception))

    def test_empty_allows_nobody(self):
        self.assertEqual(x.clients(x.parse_allowlist("# nobody yet\n")), [])

    def test_colliding_inner_addresses_are_refused(self):
        real = x.inner_ipv4
        try:
            x.inner_ipv4 = lambda _a: ipaddress.IPv4Address("100.64.0.1")
            with self.assertRaises(x.ConfigError):
                x.clients([A, B])
        finally:
            x.inner_ipv4 = real

    def test_one_tunnel_per_client(self):
        rows = x.clients([A, B, C])
        self.assertEqual([r[0] for r in rows], ["fx0", "fx1", "fx2"])
        self.assertEqual(rows[1][2], x.fips_address(B))


class Firewall(unittest.TestCase):
    def ruleset(self, npubs=(A, B), extra=()):
        return x.nft_ruleset(x.clients(list(npubs)), "eth0", extra)

    def test_only_allowed_fips_addresses_get_in(self):
        rs = self.ruleset()
        self.assertIn(f"elements = {{ {x.fips_address(A)}, {x.fips_address(B)} }}", rs)
        self.assertNotIn(str(x.fips_address(C)), rs)
        mesh_in = rs.split("chain mesh_in {")[1].split("chain forward")[0].strip().rstrip("}")
        # New traffic only from @clients6, then a final drop.
        self.assertIn("ip6 saddr @clients6 meta l4proto 4 accept", mesh_in)
        self.assertIn("ip6 saddr @clients6 udp dport 53 accept", mesh_in)
        self.assertTrue(mesh_in.strip().endswith("drop"))
        for line in mesh_in.strip().splitlines():
            if "accept" in line and "@clients6" not in line:
                self.assertTrue("established" in line or "icmpv6" in line, line)

    def test_forwarding_is_default_deny_and_source_bound(self):
        rs = self.ruleset()
        fwd = rs.split("chain forward {")[1].split("chain postrouting")[0]
        self.assertIn("policy drop;", fwd)
        self.assertIn(f'"fx0" . {x.inner_ipv4(x.fips_address(A))}', rs)
        self.assertIn(f'"fx1" . {x.inner_ipv4(x.fips_address(B))}', rs)
        self.assertIn('iifname . ip saddr @client_src ip daddr != @blocked4 ip daddr != @blocked_dyn accept', fwd)
        # Into a tunnel only as a reply.
        self.assertIn('oifname "fx*" ct state established,related accept', fwd)
        # No other accept in forward.
        self.assertEqual(fwd.count("accept"), 2)

    def test_private_and_local_destinations_are_blocked(self):
        rs = self.ruleset(extra=["203.0.113.7/32", "198.51.100.9"])
        for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                     "100.64.0.0/10", "169.254.0.0/16", "203.0.113.7/32", "198.51.100.9/32"]:
            self.assertIn(cidr, rs)

    def test_nat_only_for_clients(self):
        rs = self.ruleset()
        self.assertIn('oifname "eth0" ip saddr @clients4 masquerade', rs)

    def test_tunnels_reach_nothing_on_the_exit(self):
        self.assertIn('iifname "fx*" drop', self.ruleset())

    def test_no_clients_still_loads_and_allows_nothing(self):
        rs = self.ruleset(npubs=())
        self.assertNotIn("elements = {  }", rs)
        self.assertIn("policy drop;", rs)

    def test_bad_interface_and_cidr_are_refused(self):
        with self.assertRaises(x.ConfigError):
            x.nft_ruleset([], 'eth0" accept #')
        with self.assertRaises(ValueError):
            x.nft_ruleset([], "eth0", ["not-a-cidr"])


class Publish(unittest.TestCase):
    def test_entries(self):
        self.assertEqual(
            x.parse_publish("8000=192.168.1.20:8000, 8080=172.17.0.1:80\n 1883=10.0.0.5"),
            [(8000, ipaddress.IPv4Address("192.168.1.20"), 8000),
             (8080, ipaddress.IPv4Address("172.17.0.1"), 80),
             (1883, ipaddress.IPv4Address("10.0.0.5"), 1883)])

    def test_empty_publishes_nothing(self):
        self.assertEqual(x.parse_publish("  "), [])

    def test_bad_entries_are_refused(self):
        for spec in [
            "8000", "8000=", "8000=nas.local:8000", "8000=[::1]:8000",
            "8000=192.168.1.256:8000", "8000=192.168.01.20:8000", "0=192.168.1.20:80",
            "70000=192.168.1.20:80", "8000=192.168.1.20:0", "8000=192.168.1.20:8000/udp",
            "53=192.168.1.2:53",  # the exit's DNS
            "8000=127.0.0.1:8000", "8000=0.0.0.0:8000", "8000=100.64.0.7:80",
            "8000=224.0.0.1:80", "8000=255.255.255.255:80",
            "8000=192.168.1.20:8000 8000=192.168.1.21:8000",  # twice
            '8000=192.168.1.20:8000"; accept',
        ]:
            with self.assertRaises(x.ConfigError, msg=spec):
                x.parse_publish(spec)

    def test_only_allowed_clients_reach_published_ports(self):
        rs = x.nft_ruleset(x.clients([A]), "eth0", published=x.parse_publish("8000=192.168.1.20 8080=172.17.0.1:80"))
        self.assertIn("elements = { 8000, 8080 }", rs)
        self.assertIn("ip6 saddr @clients6 tcp dport @published_tcp accept", rs)
        # Publishing is a relay on the exit, not forwarding: the private-range
        # block in forward is unchanged and the LAN host is not in the ruleset.
        self.assertNotIn("192.168.1.20", rs)
        fwd = rs.split("chain forward {")[1].split("chain postrouting")[0]
        self.assertEqual(fwd.count("accept"), 2)
        self.assertIn("192.168.0.0/16", rs)

    def test_nothing_published_leaves_the_set_empty(self):
        rs = x.nft_ruleset(x.clients([A]), "eth0")
        published = rs.split("set published_tcp {")[1].split("}")[0]
        self.assertNotIn("elements", published)

    def test_cli(self):
        import io, contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(x.main(["publish", "8000=192.168.1.20"]), 0)
        self.assertEqual(out.getvalue(), "8000 192.168.1.20 8000\n")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(x.main(["publish", "8000=nope"]), 1)


class PublicIp(unittest.TestCase):
    def test_lookup_spec(self):
        self.assertEqual(x.parse_lookup(""), x.DEFAULT_PUBLIC_IP_LOOKUP)
        self.assertEqual(x.parse_lookup(" off "), [])
        self.assertEqual(x.parse_lookup("https://a.example/ip, http://10.0.0.2:8081/ip"),
                         ["https://a.example/ip", "http://10.0.0.2:8081/ip"])
        for spec in ["ftp://a.example", "a.example", "https://a.example/ip'; rm", "OFF",
                     " ".join(["https://a.example"] * (x.MAX_LOOKUP_URLS + 1))]:
            with self.assertRaises(x.ConfigError, msg=spec):
                x.parse_lookup(spec)

    def test_defaults_are_https(self):
        for url in x.DEFAULT_PUBLIC_IP_LOOKUP:
            self.assertTrue(url.startswith("https://"), url)

    def test_only_a_public_ipv4_is_an_answer(self):
        self.assertEqual(x.public_ipv4("8.8.4.4\n"), ipaddress.IPv4Address("8.8.4.4"))
        for answer in ["192.168.1.1", "10.1.2.3", "100.64.0.1",  # behind CGNAT: not ours
                       "127.0.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "203.0.113.7",
                       "2001:db8::1", "2a02:fe1::1", "<html>rate limited</html>", "", "1.2.3"]:
            self.assertIsNone(x.public_ipv4(answer), answer)

    def fetcher(self, answers):
        def fetch(url):
            a = answers[url]
            if isinstance(a, Exception):
                raise a
            return a
        return fetch

    def test_every_valid_answer_is_blocked(self):
        # A source that disagrees adds a block; it cannot lift one.
        got = x.public_ips(["a", "b", "c", "d"], self.fetcher({
            "a": "198.18.0.1",  # not public: ignored
            "b": "8.8.4.4\n", "c": "1.0.0.1", "d": "8.8.4.4"}))
        self.assertEqual(got, [ipaddress.IPv4Address("1.0.0.1"), ipaddress.IPv4Address("8.8.4.4")])

    def test_one_source_is_enough_and_failures_are_logged(self):
        logged = []
        got = x.public_ips(["a", "b"], self.fetcher({"a": OSError("timed out"), "b": "1.0.0.1"}),
                           log=logged.append)
        self.assertEqual(got, [ipaddress.IPv4Address("1.0.0.1")])
        self.assertEqual(len(logged), 1)
        self.assertIn("timed out", logged[0])

    def test_no_answer_is_an_error(self):
        with self.assertRaises(x.ConfigError) as e:
            x.public_ips(["a", "b"], self.fetcher({"a": OSError("refused"), "b": "192.168.1.1"}))
        self.assertIn("refused", str(e.exception))
        self.assertIn("192.168.1.1", str(e.exception))

    def test_off_asks_nobody(self):
        self.assertEqual(x.public_ips([], self.fetcher({})), [])

    def test_ruleset_blocks_the_public_address(self):
        rs = x.nft_ruleset(x.clients([A]), "eth0", public=[ipaddress.IPv4Address("8.8.4.4")])
        dyn = rs.split("set blocked_dyn {")[1].split("}")[0]
        self.assertIn("elements = { 8.8.4.4 ", dyn)
        fwd = rs.split("chain forward {")[1].split("chain postrouting")[0]
        self.assertIn("ip daddr != @blocked_dyn accept", fwd)
        # No address (lookup off): the set exists, empty, so updates can fill it.
        rs = x.nft_ruleset(x.clients([A]), "eth0")
        self.assertNotIn("elements", rs.split("set blocked_dyn {")[1].split("}")[0])

    def test_update_is_one_atomic_swap(self):
        self.assertEqual(x.nft_public_ip(["1.0.0.1", "8.8.4.4"]),
                         "flush set inet fips_exit blocked_dyn\n"
                         "add element inet fips_exit blocked_dyn { 1.0.0.1, 8.8.4.4 }\n")
        with self.assertRaises(ValueError):
            x.nft_public_ip(["1.0.0.1 } ; flush ruleset"])

    def test_cli(self):
        import io, contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(x.main(["public-ip", "off"]), 0)
        self.assertEqual(out.getvalue(), "\n")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(x.main(["public-ip", "http://127.0.0.1:9/"]), 1)
            self.assertEqual(x.main(["public-ip", "ftp://x"]), 1)


class FipsConfig(unittest.TestCase):
    def test_persistent_identity_and_peers(self):
        y = x.fips_yaml([f"{A}@test-de01.fips.network:2121", f"{B}@[2001:db8::1]:2121"])
        self.assertIn("persistent: true", y)
        self.assertIn("name: fips0", y)
        self.assertIn(f'npub: "{A}"', y)
        self.assertIn('addr: "[2001:db8::1]:2121"', y)

    def test_bad_peer_is_refused(self):
        for spec in [f"{A}", f"{A}@host", f'{A}@host:1"\nevil: 1', "npub1typo@h:1"]:
            with self.assertRaises(x.ConfigError, msg=spec):
                x.fips_yaml([spec])

    def test_none_means_no_peers(self):
        import io, contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(x.main(["fips-yaml", "none"]), 0)
        self.assertIn("peers: []", out.getvalue())

    def test_default_peers_are_valid(self):
        y = x.fips_yaml(x.DEFAULT_PEERS)
        self.assertEqual(y.count("- npub:"), len(x.DEFAULT_PEERS))


if __name__ == "__main__":
    unittest.main()
