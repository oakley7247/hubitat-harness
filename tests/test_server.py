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


def _settings(
    allow_security_commands: bool,
    writable_device_ids: frozenset[str] | None = None,
) -> HubitatConfig:
    """Return a config with the guarded-command flag and allowlist set as given."""
    return HubitatConfig(
        host_ip="127.0.0.1",
        port=80,
        app_id="42",
        access_token="b7c1e2f3-4a5b-6c7d-8e9f-0a1b2c3d4e5f",
        timeout_seconds=5.0,
        allow_security_commands=allow_security_commands,
        writable_device_ids=writable_device_ids,
    )


def _install(test: unittest.TestCase, hub: "_FakeHub", settings: HubitatConfig) -> None:
    """Point the module's client and settings at a fake hub for one test."""
    for patcher in (
        mock.patch.object(server, "_client", hub),
        mock.patch.object(server, "_config", settings),
    ):
        patcher.start()
        test.addCleanup(patcher.stop)


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


class FailClosedTests(unittest.TestCase):
    """The guarded check must refuse when it cannot tell, not permit."""

    def test_a_device_missing_its_capability_list_is_refused(self):
        """A device whose capabilities the hub omitted is refused, not allowed.

        The command is `refresh`, which no command-name rule covers, so the
        only thing that can refuse it is the capability-shape check. Reading a
        missing list as "no capabilities" would let it through.
        """
        no_capabilities = {
            "id": "200",
            "label": "Front Door",
            "commands": [{"command": "refresh"}],
            "attributes": [],
        }
        hub = _FakeHub(no_capabilities)
        _install(self, hub, _settings(False))

        with self.assertRaises(MakerApiError) as caught:
            server.send_command("200", "refresh")
        self.assertEqual(hub.sent, [])
        self.assertIn("did not report what device", str(caught.exception))

    def test_a_capability_list_of_unusable_entries_is_refused(self):
        """A non-empty list that yields no capability name is refused.

        `[None]` passes a shape check but parses to nothing, which reads
        identically to "this device guards nothing" — the fail-open case a
        raw-shape check would miss.
        """
        hub = _FakeHub(
            {
                "id": "200",
                "label": "Front Door",
                "capabilities": [None, 123],
                "commands": [{"command": "refresh"}],
                "attributes": [],
            }
        )
        _install(self, hub, _settings(False))

        with self.assertRaises(MakerApiError) as caught:
            server.send_command("200", "refresh")
        self.assertEqual(hub.sent, [])
        self.assertIn("did not report what device", str(caught.exception))

    def test_a_capability_reported_as_an_object_still_guards(self):
        """Hubitat's object form of a capability entry is matched, not skipped.

        `refresh` is used for the same reason as above: it isolates the
        capability parsing from the command-name rule.
        """
        hub = _FakeHub(
            {
                "id": "200",
                "label": "Front Door",
                "capabilities": [{"Lock": ["lock", "unlock"]}],
                "commands": [{"command": "refresh"}],
                "attributes": [],
            }
        )
        _install(self, hub, _settings(False))

        with self.assertRaises(MakerApiError) as caught:
            server.send_command("200", "refresh")
        self.assertEqual(hub.sent, [])
        self.assertIn("guards a physical or safety boundary", str(caught.exception))

    def test_a_door_wired_as_a_plain_switch_is_refused_by_command_name(self):
        """`open` is refused on a device reporting only Switch.

        A garage door, gate, or door strike is commonly wired as a plain relay
        that declares no guarded capability, so the capability check alone
        would let it through.
        """
        relay = {
            "id": "300",
            "label": "Side Gate",
            "capabilities": ["Switch"],
            "commands": [{"command": "open"}, {"command": "close"}, {"command": "on"}],
            "attributes": [],
        }
        hub = _FakeHub(relay)
        _install(self, hub, _settings(False))

        with self.assertRaises(MakerApiError) as caught:
            server.send_command("300", "open")
        self.assertEqual(hub.sent, [])
        self.assertIn("opens, closes, locks", str(caught.exception))

    def test_an_ordinary_command_on_that_same_switch_still_works(self):
        """`on` passes on the same device, so the name check is not a blanket block."""
        relay = {
            "id": "300",
            "label": "Side Gate",
            "capabilities": ["Switch"],
            "commands": [{"command": "open"}, {"command": "on"}],
            "attributes": [],
        }
        hub = _FakeHub(relay)
        _install(self, hub, _settings(False))

        server.send_command("300", "on")
        self.assertEqual(hub.sent, [("300", "on", None)])


class WritableAllowlistTests(unittest.TestCase):
    def test_a_device_outside_the_allowlist_is_refused(self):
        """With an allowlist set, a device not on it cannot be commanded."""
        hub = _FakeHub(_SWITCH)
        _install(self, hub, _settings(False, writable_device_ids=frozenset({"999"})))

        with self.assertRaises(MakerApiError) as caught:
            server.send_command("154", "on")
        self.assertEqual(hub.sent, [])
        self.assertIn("HUBITAT_WRITABLE_DEVICE_IDS", str(caught.exception))

    def test_a_device_on_the_allowlist_is_permitted(self):
        """The same command succeeds once the device is listed."""
        hub = _FakeHub(_SWITCH)
        _install(self, hub, _settings(False, writable_device_ids=frozenset({"154"})))

        server.send_command("154", "on")
        self.assertEqual(hub.sent, [("154", "on", None)])

    def test_setting_a_mode_is_refused_while_an_allowlist_is_in_force(self):
        """A mode change is refused when the allowlist is set, even with the flag on.

        A mode has no device id, so it can never appear in the list — an
        operator who enumerated writable devices has not authorized it. The
        guarded-command flag is on here so that only the allowlist can refuse.
        """
        hub = _FakeHub(_SWITCH)
        _install(self, hub, _settings(True, writable_device_ids=frozenset({"154"})))

        with self.assertRaises(MakerApiError) as caught:
            server.set_mode("2")
        self.assertEqual(hub.sent, [])
        self.assertIn("HUBITAT_WRITABLE_DEVICE_IDS", str(caught.exception))

    def test_setting_a_mode_still_works_with_no_allowlist(self):
        """Without an allowlist the mode change proceeds, isolating the cause."""
        hub = _FakeHub(_SWITCH)
        _install(self, hub, _settings(True, writable_device_ids=None))

        server.set_mode("2")
        self.assertEqual(hub.sent, [("mode", "2", None)])


class PayloadBoundTests(unittest.TestCase):
    def test_an_oversized_hub_response_is_trimmed_before_it_reaches_the_model(self):
        """A huge device list is cut down and the cut is declared, not hidden."""
        hub = _FakeHub(_SWITCH)
        hub.device = _SWITCH
        _install(self, hub, _settings(False))
        huge = [{"id": str(index), "label": "x" * 500} for index in range(1000)]

        result = server._wrap(huge)

        self.assertIn("truncated", result)
        self.assertLess(len(result["data"]), len(huge))
        self.assertGreater(len(result["data"]), 0, "trimming removed everything")

    def test_a_normal_response_is_passed_through_untouched(self):
        """A small payload is not trimmed, proving the bound does not over-trigger."""
        result = server._wrap([{"id": "154", "label": "Porch Light"}])
        self.assertNotIn("truncated", result)
        self.assertEqual(result["data"], [{"id": "154", "label": "Porch Light"}])


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
