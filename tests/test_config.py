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
        self.assertIn("public address", str(caught.exception))

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

    def test_out_of_range_timeout_is_refused(self):
        """A timeout outside the sane band is refused at startup, not at 3am."""
        env = _env()
        env["HUBITAT_TIMEOUT_SECONDS"] = "3600"
        with mock.patch.dict("os.environ", env, clear=True):
            with self.assertRaises(ConfigError):
                load_config()


if __name__ == "__main__":
    unittest.main()
