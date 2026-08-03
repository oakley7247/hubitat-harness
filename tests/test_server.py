# =============================================================================
# test_server.py — proves the tool layer's two gates: a command must be one the
# device itself reports, and a device guarding a physical boundary is off
# limits unless the hub owner opted in.
#
# Part of: hubitat-claude test suite. Tests: src/hubitat_claude/server.py.
# =============================================================================
"""Tests for the MCP tool layer's command allowlist and guarded-device gate."""

import unittest
from typing import Any
from unittest import mock

from hubitat_claude import server
from hubitat_claude.config import HubitatConfig
from hubitat_claude.maker_api import MakerApiError

_SWITCH = {
    "id": "154",
    "label": "Porch Light",
    "capabilities": ["Switch", "SwitchLevel"],
    "commands": [{"command": "on"}, {"command": "off"}, {"command": "setLevel"}],
    "attributes": [{"name": "switch", "currentValue": "off", "dataType": "ENUM"}],
}

_LOCK = {
    "id": "200",
    "label": "Front Door",
    "capabilities": ["Lock"],
    "commands": [{"command": "lock"}, {"command": "unlock"}],
    "attributes": [{"name": "lock", "currentValue": "locked", "dataType": "ENUM"}],
}


class _FakeHub:
    """Stands in for MakerApiClient, recording the commands it is asked to send."""

    def __init__(self, device: dict[str, Any]) -> None:
        self.device = device
        self.sent: list[tuple[str, str, str | None]] = []

    def get_device(self, device_id: str) -> dict[str, Any]:
        return self.device

    def send_command(self, device_id: str, command: str, argument: str | None = None) -> Any:
        self.sent.append((device_id, command, argument))
        return self.device

    def set_mode(self, mode_id: str) -> Any:
        self.sent.append(("mode", mode_id, None))
        return [{"id": 1, "name": "Day", "active": True}]


def _settings(allow_security_commands: bool) -> HubitatConfig:
    """Return a config with the guarded-command flag set as given."""
    return HubitatConfig(
        host_ip="127.0.0.1",
        port=80,
        app_id="42",
        access_token="b7c1e2f3-4a5b-6c7d-8e9f-0a1b2c3d4e5f",
        timeout_seconds=5.0,
        allow_security_commands=allow_security_commands,
    )


class CommandAllowlistTests(unittest.TestCase):
    def setUp(self) -> None:
        self.hub = _FakeHub(_SWITCH)
        for patcher in (
            mock.patch.object(server, "_client", self.hub),
            mock.patch.object(server, "_config", _settings(False)),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_a_command_the_device_reports_is_sent(self):
        """A supported command reaches the hub, proving the gate permits real use."""
        server.send_command("154", "on")
        self.assertEqual(self.hub.sent, [("154", "on", None)])

    def test_a_command_the_device_does_not_report_is_refused(self):
        """An unsupported command is refused before any request goes out."""
        with self.assertRaises(MakerApiError) as caught:
            server.send_command("154", "unlock")
        self.assertEqual(self.hub.sent, [])
        self.assertIn("does not accept", str(caught.exception))

    def test_the_refusal_lists_what_the_device_does_accept(self):
        """The error names the real commands, so the model can correct itself."""
        with self.assertRaises(MakerApiError) as caught:
            server.send_command("154", "explode")
        self.assertIn("off, on, setLevel", str(caught.exception))

    def test_hub_data_is_returned_labelled_as_untrusted(self):
        """Device text reaches the model wrapped as data, never as instructions."""
        result = server.send_command("154", "on")
        self.assertEqual(result["trust"], "untrusted_data")
        self.assertIn("not instructions", result["warning"])


class GuardedDeviceTests(unittest.TestCase):
    def test_a_lock_is_refused_by_default(self):
        """A lock command is refused when the owner has not opted in."""
        hub = _FakeHub(_LOCK)
        for patcher in (
            mock.patch.object(server, "_client", hub),
            mock.patch.object(server, "_config", _settings(False)),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

        with self.assertRaises(MakerApiError) as caught:
            server.send_command("200", "unlock")
        self.assertEqual(hub.sent, [], "the unlock reached the hub despite being refused")
        self.assertIn("HUBITAT_ALLOW_SECURITY_COMMANDS", str(caught.exception))

    def test_a_lock_is_permitted_once_the_owner_opts_in(self):
        """The same command succeeds with the flag on, proving the gate is the cause."""
        hub = _FakeHub(_LOCK)
        for patcher in (
            mock.patch.object(server, "_client", hub),
            mock.patch.object(server, "_config", _settings(True)),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

        server.send_command("200", "unlock")
        self.assertEqual(hub.sent, [("200", "unlock", None)])

    def test_an_ordinary_switch_is_unaffected_by_the_gate(self):
        """A non-guarded device works with the flag off — the gate is not a blanket block."""
        hub = _FakeHub(_SWITCH)
        for patcher in (
            mock.patch.object(server, "_client", hub),
            mock.patch.object(server, "_config", _settings(False)),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

        server.send_command("154", "setLevel", "50")
        self.assertEqual(hub.sent, [("154", "setLevel", "50")])


class ModeTests(unittest.TestCase):
    def test_setting_a_mode_is_refused_by_default(self):
        """Mode changes are gated too, because they commonly drive security rules."""
        hub = _FakeHub(_SWITCH)
        for patcher in (
            mock.patch.object(server, "_client", hub),
            mock.patch.object(server, "_config", _settings(False)),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

        with self.assertRaises(MakerApiError):
            server.set_mode("2")
        self.assertEqual(hub.sent, [])

    def test_setting_a_mode_is_permitted_once_the_owner_opts_in(self):
        """With the flag on the mode change goes through, proving the gate is the cause."""
        hub = _FakeHub(_SWITCH)
        for patcher in (
            mock.patch.object(server, "_client", hub),
            mock.patch.object(server, "_config", _settings(True)),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

        server.set_mode("2")
        self.assertEqual(hub.sent, [("mode", "2", None)])


if __name__ == "__main__":
    unittest.main()
