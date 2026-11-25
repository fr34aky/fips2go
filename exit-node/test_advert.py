"""Unit tests for advert.py: python3 -I -m unittest discover -s exit-node"""

import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import advert as a  # noqa: E402
import exitctl as x  # noqa: E402

KEY = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000003")
ZERO = bytes(32)


class Schnorr(unittest.TestCase):
    def test_bip340_vector_0(self):
        self.assertEqual(
            a.pubkey(KEY).hex().upper(),
            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        )
        sig = a.sign(ZERO, KEY, ZERO)
        self.assertEqual(
            sig.hex().upper(),
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
            "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
        )
        self.assertTrue(a.verify(ZERO, a.pubkey(KEY), sig))

    def test_a_changed_message_key_or_signature_does_not_verify(self):
        msg = hashlib.sha256(b"advert").digest()
        sig = a.sign(msg, KEY, os.urandom(32))
        pub = a.pubkey(KEY)
        self.assertTrue(a.verify(msg, pub, sig))
        self.assertFalse(a.verify(hashlib.sha256(b"other").digest(), pub, sig))
        self.assertFalse(a.verify(msg, a.pubkey(bytes(31) + b"\x05"), sig))
        self.assertFalse(a.verify(msg, pub, sig[:-1] + bytes([sig[-1] ^ 1])))
        self.assertFalse(a.verify(msg, pub, sig[:40]))

    def test_a_key_outside_the_group_is_refused(self):
        for bad in (ZERO, bytes.fromhex("ff" * 32)):
            with self.assertRaises(a.AdvertError):
                a.pubkey(bad)


class KeyFile(unittest.TestCase):
    def read(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".key") as f:
            f.write(text)
            f.flush()
            return a.read_key(f.name)

    def test_hex_and_nsec_give_the_same_key(self):
        self.assertEqual(self.read(KEY.hex() + "\n"), KEY)
        # The nsec of that key, built with the same bech32 exitctl checks.
        nsec = "nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsmhltgl"
        self.assertEqual(self.read(nsec + "\n"), bytes(31) + b"\x01")

    def test_a_typo_or_an_npub_is_not_a_key(self):
        for bad in ("nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsmhltgx",
                    "npub12yu4dny6chzwghtq68ygmkyj7ugz93e403skz3y075mykjsheg7sp0yyzz", "", "abc"):
            with self.assertRaises(a.AdvertError):
                self.read(bad)


class Event(unittest.TestCase):
    def event(self, **kw):
        args = dict(access="open", name="My exit", about="Zurich", ttl=10800, now=1_800_000_000, aux=ZERO)
        args.update(kw)
        return a.build_event(KEY, **args)

    def test_shape_id_and_signature(self):
        e = self.event()
        self.assertEqual(e["kind"], 30078)
        self.assertEqual(e["content"], "")
        self.assertEqual(e["pubkey"], a.pubkey(KEY).hex())
        self.assertEqual(
            e["tags"],
            [["d", "fips-exit"], ["v", "1"], ["access", "open"], ["name", "My exit"],
             ["about", "Zurich"], ["expiration", "1800010800"]],
        )
        body = json.dumps([0, e["pubkey"], e["created_at"], 30078, e["tags"], ""], separators=(",", ":"),
                          ensure_ascii=False)
        self.assertEqual(e["id"], hashlib.sha256(body.encode()).hexdigest())
        self.assertTrue(a.verify(bytes.fromhex(e["id"]), bytes.fromhex(e["pubkey"]), bytes.fromhex(e["sig"])))

    def test_name_and_about_are_optional_and_tidied(self):
        e = self.event(name="", about="")
        self.assertEqual([t[0] for t in e["tags"]], ["d", "v", "access", "expiration"])
        e = self.event(name="  two\n lines\t", about="")
        self.assertIn(["name", "two lines"], e["tags"])
        self.assertIn(["name", "Zürich ☕"], self.event(name="Zürich ☕")["tags"])

    def test_bad_input_is_refused(self):
        for kw in (dict(access="paid"), dict(name="x" * 41), dict(about="x" * 201),
                   dict(name="bell\x07"), dict(ttl=60), dict(ttl=31 * 86400)):
            with self.assertRaises(a.AdvertError, msg=kw):
                self.event(**kw)


class Relays(unittest.TestCase):
    NPUB = "npub12yu4dny6chzwghtq68ygmkyj7ugz93e403skz3y075mykjsheg7sp0yyzz"

    def test_urls(self):
        self.assertEqual(a.parse_relay("wss://relay.example.org"), (True, "relay.example.org", 443, "/", None))
        self.assertEqual(a.parse_relay("ws://10.0.0.5:7777/nostr"), (False, "10.0.0.5", 7777, "/nostr", None))
        self.assertEqual(
            a.parse_relay(f"ws://{self.NPUB}.fips:7777"), (False, f"{self.NPUB}.fips", 7777, "/", self.NPUB)
        )

    def test_bad_urls_are_refused(self):
        for bad in ("relay.example.org", "http://relay.example.org", "wss://relay.example.org:99999",
                    "ws://home.fips", f"wss://{self.NPUB}.fips", "wss://exa mple.org", "wss://x/ y"):
            with self.assertRaises(a.AdvertError, msg=bad):
                a.parse_relay(bad)

    def test_the_list_needs_one_relay_and_has_a_ceiling(self):
        self.assertEqual(a.parse_relays("wss://a.example, ws://b.example"), ["wss://a.example", "ws://b.example"])
        with self.assertRaises(a.AdvertError):
            a.parse_relays("")
        with self.assertRaises(a.AdvertError):
            a.parse_relays(" ".join(f"wss://r{i}.example" for i in range(9)))

    def test_check_command(self):
        self.assertEqual(a.main(["check", "open", "My exit", "", "wss://relay.example.org"]), 0)
        self.assertEqual(a.main(["check", "open", "My exit", ""]), 1)
        self.assertEqual(a.main(["check", "paid", "", "", "wss://relay.example.org"]), 1)


if __name__ == "__main__":
    unittest.main()
