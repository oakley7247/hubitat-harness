# =============================================================================
# test_automations.py — proves the rules client's safety properties against a
# real loopback HTTP server, not a mocked-out socket.
#
# Part of: hubitat-claude test suite. Tests: src/hubitat_claude/automations.py
# and the writable-device gate the rule tools add in server.py. The tests drive
# the client through its public methods so URL building, body encoding, the
# refusal path, and the token-withholding all run together.
# =============================================================================
"""Tests for the Claude Automations rules client and the rule tool gate."""

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from unittest import mock

from hubitat_claude import server
from hubitat_claude.automations import (
    AutomationsClient,
    AutomationsError,
    AutomationsNotConfiguredError,
    collect_device_ids,
)
from hubitat_claude.config import HubitatConfig

_TOKEN = "b7c1e2f3-4a5b-6c7d-8e9f-0a1b2c3d4e5f"

_RULE = {
    "name": "Kitchen counter on motion",
    "trigger": {
        "type": "attribute",
        "deviceId": "241",
        "attribute": "motion",
        "changesTo": "active",
    },
    "actions": [{"type": "command", "deviceId": "357", "command": "on"}],
}


class _Handler(BaseHTTPRequestHandler):
    """Serves whatever the owning test configured, and records every request."""

    def _serve(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.received.append((self.command, self.path, body))  # type: ignore[attr-defined]
        status, reply, headers = self.server.reply  # type: ignore[attr-defined]
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        if reply:
            self.wfile.write(reply)

    # These names are fixed by BaseHTTPRequestHandler's dispatch, not chosen here.
    def do_GET(self) -> None:
        self._serve()

    def do_POST(self) -> None:
        self._serve()

    def do_PUT(self) -> None:
        self._serve()

    def do_DELETE(self) -> None:
        self._serve()

    def log_message(self, *args: object) -> None:
        """Silence the default stderr request log during tests."""


def _start_server(
    test: unittest.TestCase,
    status: int = 200,
    body: bytes = b"{}",
    headers: dict[str, str] | None = None,
):
    """Start a loopback HTTP server, register its shutdown, and return (server, port).

    Cleanups run last-registered-first, so the loop stops before the listening
    socket closes.
    """
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.received = []  # type: ignore[attr-defined]
    httpd.reply = (status, body, headers or {"Content-Type": "application/json"})  # type: ignore[attr-defined]
    test.addCleanup(httpd.server_close)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    test.addCleanup(httpd.shutdown)
    return httpd, httpd.server_address[1]


def _settings(port: int, *, configured: bool = True) -> HubitatConfig:
    """Return a config pointed at the loopback server."""
    return HubitatConfig(
        host_ip="127.0.0.1",
        port=port,
        app_id="42",
        access_token=_TOKEN,
        timeout_seconds=5.0,
        allow_security_commands=False,
        writable_device_ids=None,
        automations_app_id="77" if configured else None,
        automations_token=_TOKEN if configured else None,
    )


class ClientTests(unittest.TestCase):
    def test_creating_a_rule_posts_the_spec_as_json(self):
        """The spec reaches the hub as a JSON body on POST /rules."""
        httpd, port = _start_server(self, status=201, body=b'{"ruleId": "99"}')
        client = AutomationsClient(_settings(port))

        result = client.create_rule(_RULE)

        method, path, body = httpd.received[0]  # type: ignore[attr-defined]
        self.assertEqual(method, "POST")
        self.assertIn("/apps/api/77/rules", path)
        self.assertEqual(json.loads(body), _RULE)
        self.assertEqual(result, {"ruleId": "99"})

    def test_deleting_a_rule_uses_the_delete_method(self):
        """Deletion is a DELETE, not a GET with a verb in the path."""
        httpd, port = _start_server(self, body=b'{"deleted": true}')
        AutomationsClient(_settings(port)).delete_rule("99")

        method, path, _ = httpd.received[0]  # type: ignore[attr-defined]
        self.assertEqual(method, "DELETE")
        self.assertIn("/apps/api/77/rules/99", path)

    def test_a_refusal_carries_the_hubs_reasons(self):
        """A 400 surfaces the validator's problems, which is what makes a fix possible."""
        _, port = _start_server(
            self,
            status=400,
            body=json.dumps(
                {
                    "error": "The rule was refused.",
                    "problems": ["actions[0].command nope is not a command"],
                }
            ).encode(),
        )
        client = AutomationsClient(_settings(port))

        with self.assertRaises(AutomationsError) as caught:
            client.create_rule(_RULE)

        self.assertIn("nope is not a command", str(caught.exception))

    def test_an_auth_failure_never_echoes_the_token(self):
        """Hubitat echoes a rejected token in its 401 body; that body is never read."""
        _, port = _start_server(
            self,
            status=401,
            body=f"<oauth><error_description>{_TOKEN}</error_description></oauth>".encode(),
        )
        client = AutomationsClient(_settings(port))

        with self.assertRaises(AutomationsError) as caught:
            client.list_rules()

        self.assertNotIn(_TOKEN, str(caught.exception))

    def test_a_redirect_is_refused(self):
        """Following a 3xx would hand the token to whatever host it names."""
        _, port = _start_server(
            self, status=302, body=b"", headers={"Location": "http://example.com/"}
        )
        client = AutomationsClient(_settings(port))

        with self.assertRaises(AutomationsError) as caught:
            client.list_rules()

        self.assertNotIn(_TOKEN, str(caught.exception))

    def test_a_non_numeric_rule_id_never_reaches_the_hub(self):
        """The id is a URL path segment, so it is checked before the request."""
        httpd, port = _start_server(self)
        client = AutomationsClient(_settings(port))

        with self.assertRaises(AutomationsError):
            client.get_rule("../devices")

        self.assertEqual(httpd.received, [])  # type: ignore[attr-defined]

    def test_an_oversized_spec_is_refused_before_sending(self):
        """A spec beyond the cap is stopped here rather than at the hub."""
        httpd, port = _start_server(self)
        client = AutomationsClient(_settings(port))

        with self.assertRaises(AutomationsError):
            client.create_rule({"name": "x" * 20000})

        self.assertEqual(httpd.received, [])  # type: ignore[attr-defined]

    def test_an_unconfigured_rules_app_says_so(self):
        """Without the app id and token the client refuses to build at all."""
        with self.assertRaises(AutomationsNotConfiguredError):
            AutomationsClient(_settings(80, configured=False))


class DeviceIdWalkTests(unittest.TestCase):
    def test_ids_are_found_at_every_depth(self):
        """The walk covers nested structures, not just the keys the schema names today."""
        found = collect_device_ids(
            {
                "trigger": {"deviceId": "241"},
                "conditions": [{"deviceId": "300"}],
                "actions": [{"deviceId": 357, "nested": [{"deviceId": "400"}]}],
            }
        )
        self.assertEqual(found, {"241", "300", "357", "400"})


class _FakeRules:
    """Stands in for AutomationsClient, recording what it is handed."""

    def __init__(self, existing_spec: dict[str, Any] | None = None) -> None:
        self.created: list[dict[str, Any]] = []
        self.enabled: list[tuple[str, bool]] = []
        self.existing_spec = existing_spec

    def create_rule(self, spec: dict[str, Any]) -> Any:
        self.created.append(spec)
        return {"ruleId": "99"}

    def get_rule(self, rule_id: str) -> Any:
        return {"ruleId": rule_id, "spec": self.existing_spec}

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> Any:
        self.enabled.append((rule_id, enabled))
        return {"ruleId": rule_id, "enabled": enabled}


class WritableAllowlistTests(unittest.TestCase):
    """A rule is a write path, so the operator's allowlist has to cover it."""

    def _install(
        self, writable: frozenset[str] | None, existing_spec: dict[str, Any] | None = None
    ) -> _FakeRules:
        rules = _FakeRules(existing_spec)
        settings = HubitatConfig(
            host_ip="127.0.0.1",
            port=80,
            app_id="42",
            access_token=_TOKEN,
            timeout_seconds=5.0,
            allow_security_commands=False,
            writable_device_ids=writable,
            automations_app_id="77",
            automations_token=_TOKEN,
        )
        for patcher in (
            mock.patch.object(server, "_automations", rules),
            mock.patch.object(server, "_config", settings),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        return rules

    def test_a_rule_naming_an_unlisted_device_is_refused(self):
        """The allowlist binds rule creation exactly as it binds send_command."""
        rules = self._install(frozenset({"241"}))

        with self.assertRaises(AutomationsError) as caught:
            server.create_rule(_RULE)

        self.assertIn("357", str(caught.exception))
        self.assertEqual(rules.created, [])

    def test_a_rule_inside_the_allowlist_proceeds(self):
        """The refusal above is caused by the allowlist, not by the rule itself."""
        rules = self._install(frozenset({"241", "357"}))

        server.create_rule(_RULE)

        self.assertEqual(rules.created, [_RULE])

    def test_no_allowlist_means_no_restriction(self):
        """Unset is the documented default and must not refuse anything."""
        rules = self._install(None)

        server.create_rule(_RULE)

        self.assertEqual(rules.created, [_RULE])

    def test_a_mode_changing_rule_is_refused_while_the_allowlist_is_set(self):
        """A setMode action carries no device id, so the id walk cannot see it."""
        rules = self._install(frozenset({"241"}))
        spec = {
            "name": "Arrive home",
            "trigger": {"type": "mode", "changesTo": "Evening"},
            "actions": [{"type": "setMode", "mode": "Home"}],
        }

        with self.assertRaises(AutomationsError) as caught:
            server.create_rule(spec)

        self.assertIn("mode", str(caught.exception).lower())
        self.assertEqual(rules.created, [])

    def test_a_mode_changing_rule_is_allowed_with_no_allowlist(self):
        """The refusal above comes from the allowlist, not from setMode itself."""
        rules = self._install(None)
        spec = {
            "name": "Arrive home",
            "trigger": {"type": "mode", "changesTo": "Evening"},
            "actions": [{"type": "setMode", "mode": "Home"}],
        }

        server.create_rule(spec)

        self.assertEqual(rules.created, [spec])

    def test_enabling_a_rule_naming_an_unlisted_device_is_refused(self):
        """Enabling is a write, so it is gated on the rule's own stored spec."""
        rules = self._install(frozenset({"241"}), existing_spec=_RULE)

        with self.assertRaises(AutomationsError):
            server.set_rule_enabled("99", True)

        self.assertEqual(rules.enabled, [])

    def test_enabling_fails_closed_when_the_spec_cannot_be_read(self):
        """ "Cannot tell what this rule touches" must not resolve to "let it run"."""
        rules = self._install(frozenset({"241"}), existing_spec=None)

        with self.assertRaises(AutomationsError):
            server.set_rule_enabled("99", True)

        self.assertEqual(rules.enabled, [])

    def test_disabling_is_never_refused(self):
        """Disabling only removes a rule's ability to act, so it needs no gate."""
        rules = self._install(frozenset({"241"}), existing_spec=_RULE)

        server.set_rule_enabled("99", False)

        self.assertEqual(rules.enabled, [("99", False)])


class SpecDepthTests(unittest.TestCase):
    @staticmethod
    def _deep_spec(levels: int) -> dict[str, Any]:
        """Return a spec nested `levels` deep."""
        spec: dict[str, Any] = {"name": "deep"}
        cursor = spec
        for _ in range(levels):
            cursor["nested"] = {}
            cursor = cursor["nested"]
        return spec

    def test_a_deeply_nested_spec_is_refused_rather_than_crashing(self):
        """The walk runs before the size check, so it needs its own bound."""
        with self.assertRaises(AutomationsError):
            collect_device_ids(self._deep_spec(50))

    def test_a_spec_too_deep_to_serialize_is_refused_not_crashed(self):
        """With no allowlist set the id walk never runs, so the size check must hold."""
        httpd, port = _start_server(self)
        client = AutomationsClient(_settings(port))

        with self.assertRaises(AutomationsError):
            client.create_rule(self._deep_spec(sys.getrecursionlimit() * 2))

        self.assertEqual(httpd.received, [])  # type: ignore[attr-defined]


if __name__ == "__main__":
    unittest.main()
