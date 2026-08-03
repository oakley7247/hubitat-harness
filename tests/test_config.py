# =============================================================================
# test_config.py — proves the configuration loader accepts a usable hub and
# refuses every unusable one, without ever echoing the token.
#
# Part of: hubitat-claude test suite. Tests: src/hubitat_claude/config.py.
# Each test names one property and is shaped so nothing else can satisfy it.
# =============================================================================
"""Tests for loading and validating the hub connection settings."""

import unittest
from unittest import mock

from hubitat_claude.config import ConfigError, load_config

_VALID_ENV = {
    "HUBITAT_HOST": "192.168.1.50",
    "HUBITAT_MAKER_APP_ID": "42",
    "HUBITAT_MAKER_TOKEN": "b7c1e2f3-4a5b-6c7d-8e9f-0a1b2c3d4e5f",
}


def _env(**overrides: str) -> dict[str, str]:
    """Return the valid environment with overrides applied and blanks removed."""
    merged = {**_VALID_ENV, **overrides}
    return {key: value for key, value in merged.items() if value}


class LoadConfigTests(unittest.TestCase):
    def test_accepts_a_private_hub_address(self):
        """A hub on a private network loads, with its values carried through."""
        with mock.patch.dict("os.environ", _env(), clear=True):
            config = load_config()
        self.assertEqual(config.host_ip, "192.168.1.50")
        self.assertEqual(config.app_id, "42")
        self.assertEqual(config.access_token, _VALID_ENV["HUBITAT_MAKER_TOKEN"])
        self.assertEqual(config.port, 80)

    def test_refuses_a_publicly_routable_hub_address(self):
        """A public address is refused, so the token cannot leave the network."""
        with mock.patch.dict("os.environ", _env(HUBITAT_HOST="93.184.216.34"), clear=True):
            with self.assertRaises(ConfigError) as caught:
                load_config()
        self.assertIn("not on a private network", str(caught.exception))

    def test_accepts_loopback_as_private(self):
        """Loopback counts as private, which is what makes local testing work."""
        with mock.patch.dict("os.environ", _env(HUBITAT_HOST="127.0.0.1"), clear=True):
            self.assertEqual(load_config().host_ip, "127.0.0.1")

    def test_missing_token_names_the_variable(self):
        """A missing variable is reported by name rather than as a stack trace."""
        env = _env()
        del env["HUBITAT_MAKER_TOKEN"]
        with mock.patch.dict("os.environ", env, clear=True):
            with self.assertRaises(ConfigError) as caught:
                load_config()
        self.assertIn("HUBITAT_MAKER_TOKEN", str(caught.exception))

    def test_malformed_token_is_not_echoed_in_the_error(self):
        """A rejected token never appears in the message, which gets pasted around."""
        secret = "not a valid token but still a secret"
        with mock.patch.dict("os.environ", _env(HUBITAT_MAKER_TOKEN=secret), clear=True):
            with self.assertRaises(ConfigError) as caught:
                load_config()
        self.assertNotIn(secret, str(caught.exception))
        self.assertIn("withheld", str(caught.exception))

    def test_non_numeric_app_id_is_refused(self):
        """An app id that is not digits is refused before it can reach a URL."""
        with mock.patch.dict("os.environ", _env(HUBITAT_MAKER_APP_ID="4a"), clear=True):
            with self.assertRaises(ConfigError):
                load_config()

    def test_security_commands_are_disabled_unless_asked_for(self):
        """The guarded-command flag defaults to off when the variable is unset."""
        with mock.patch.dict("os.environ", _env(), clear=True):
            self.assertFalse(load_config().allow_security_commands)

    def test_security_commands_enable_on_explicit_true(self):
        """The flag turns on for an explicit true, which is the documented value."""
        env = _env()
        env["HUBITAT_ALLOW_SECURITY_COMMANDS"] = "true"
        with mock.patch.dict("os.environ", env, clear=True):
            self.assertTrue(load_config().allow_security_commands)

    def test_unrecognized_flag_value_is_refused_not_guessed(self):
        """An unparseable flag fails closed rather than defaulting either way."""
        env = _env()
        env["HUBITAT_ALLOW_SECURITY_COMMANDS"] = "maybe"
        with mock.patch.dict("os.environ", env, clear=True):
            with self.assertRaises(ConfigError):
                load_config()

    def test_non_ascii_digit_port_is_refused(self):
        """A Unicode digit is refused, rather than crashing or silently converting."""
        env = _env()
        env["HUBITAT_PORT"] = "8²"
        with mock.patch.dict("os.environ", env, clear=True):
            with self.assertRaises(ConfigError):
                load_config()

    def test_carrier_grade_nat_address_is_refused(self):
        """100.64.0.0/10 is refused: it is routable beyond the local network.

        It is not `is_global`, so a deny-public check would have admitted it.
        """
        with mock.patch.dict("os.environ", _env(HUBITAT_HOST="100.64.1.1"), clear=True):
            with self.assertRaises(ConfigError):
                load_config()

    def test_ipv4_mapped_public_address_is_refused(self):
        """::ffff:8.8.8.8 is refused: the traffic goes to the embedded IPv4 host."""
        with mock.patch.dict("os.environ", _env(HUBITAT_HOST="::ffff:8.8.8.8"), clear=True):
            with self.assertRaises(ConfigError):
                load_config()

    def test_sixtofour_public_address_is_refused(self):
        """A 6to4 address embedding a public IPv4 is refused for the same reason."""
        with mock.patch.dict("os.environ", _env(HUBITAT_HOST="2002:0808:0808::1"), clear=True):
            with self.assertRaises(ConfigError):
                load_config()

    def test_teredo_address_embedding_a_public_client_is_refused(self):
        """A Teredo address is refused despite CPython calling 2001::/32 private.

        The embedded client address is where the traffic goes, so judging the
        wrapper would admit a public destination outright. This literal encodes
        8.8.8.8 as its client — the client field is stored bitwise-inverted, so
        8.8.8.8 appears as f7f7:f7f7.
        """
        teredo = "2001:0:4136:e378:8000:63bf:f7f7:f7f7"
        with mock.patch.dict("os.environ", _env(HUBITAT_HOST=teredo), clear=True):
            with self.assertRaises(ConfigError):
                load_config()

    def test_teredo_address_embedding_a_private_client_is_accepted(self):
        """A Teredo address whose client is itself private is allowed through.

        The positive half of the rule: the check judges the embedded
        destination, so it must permit one that really is on a private network
        rather than rejecting the address family wholesale.
        """
        teredo = "2001:0:4136:e378:8000:63bf:3fff:fdd2"  # client 192.0.2.45
        with mock.patch.dict("os.environ", _env(HUBITAT_HOST=teredo), clear=True):
            self.assertEqual(load_config().host_ip, teredo)

    def test_private_ipv6_address_is_accepted(self):
        """A unique-local IPv6 hub loads, proving the check is not IPv4-only."""
        with mock.patch.dict("os.environ", _env(HUBITAT_HOST="fd00::1"), clear=True):
            self.assertEqual(load_config().host_ip, "fd00::1")

    def test_writable_device_ids_default_to_unrestricted(self):
        """Leaving the allowlist unset means every device, which is the default."""
        with mock.patch.dict("os.environ", _env(), clear=True):
            self.assertIsNone(load_config().writable_device_ids)

    def test_writable_device_ids_parse_a_comma_separated_list(self):
        """A populated allowlist parses into the exact set given."""
        env = _env()
        env["HUBITAT_WRITABLE_DEVICE_IDS"] = "154, 200,7"
        with mock.patch.dict("os.environ", env, clear=True):
            self.assertEqual(load_config().writable_device_ids, frozenset({"154", "200", "7"}))

    def test_non_numeric_writable_device_id_is_refused(self):
        """A malformed entry fails at startup rather than silently never matching."""
        env = _env()
        env["HUBITAT_WRITABLE_DEVICE_IDS"] = "154,porch-light"
        with mock.patch.dict("os.environ", env, clear=True):
            with self.assertRaises(ConfigError):
                load_config()

    def test_out_of_range_timeout_is_refused(self):
        """A timeout outside the sane band is refused at startup, not at 3am."""
        env = _env()
        env["HUBITAT_TIMEOUT_SECONDS"] = "3600"
        with mock.patch.dict("os.environ", env, clear=True):
            with self.assertRaises(ConfigError):
                load_config()


if __name__ == "__main__":
    unittest.main()
