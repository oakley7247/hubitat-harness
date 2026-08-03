# =============================================================================
# test_maker_api.py — proves the Maker API client's safety properties against a
# real loopback HTTP server, not a mocked-out socket.
#
# Part of: hubitat-claude test suite. Tests: src/hubitat_claude/maker_api.py.
# The tests drive the client through its public methods so they exercise URL
# building, the redirect refusal, the size cap, and JSON parsing together —
# calling the private request helper directly would skip exactly the layers
# where a defect would hide.
# =============================================================================
"""Tests for the Hubitat Maker API HTTP client."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from hubitat_claude.config import HubitatConfig
from hubitat_claude.maker_api import (
    MakerApiClient,
    MakerApiError,
    MakerApiUnavailableError,
    validate_command_argument,
)

_TOKEN = "b7c1e2f3-4a5b-6c7d-8e9f-0a1b2c3d4e5f"


class _Handler(BaseHTTPRequestHandler):
    """Serves whatever the owning test configured, and records every request."""

    # The name is fixed by BaseHTTPRequestHandler's dispatch, not chosen here.
    def do_GET(self) -> None:
        self.server.received.append(self.path)  # type: ignore[attr-defined]
        status, body, headers = self.server.reply  # type: ignore[attr-defined]
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

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
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.received = []  # type: ignore[attr-defined]
    server.reply = (status, body, headers or {"Content-Type": "application/json"})  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    test.addCleanup(server.server_close)
    test.addCleanup(server.shutdown)
    return server, server.server_address[1]


def _config(port: int) -> HubitatConfig:
    """Return a config pointing at a loopback server on `port`."""
    return HubitatConfig(
        host_ip="127.0.0.1",
        port=port,
        app_id="42",
        access_token=_TOKEN,
        timeout_seconds=5.0,
        allow_security_commands=False,
        writable_device_ids=None,
    )


class RequestTests(unittest.TestCase):
    def test_reads_a_normal_device_list(self):
        """The happy path parses the hub's JSON and returns it intact."""
        devices = [{"id": "154", "name": "Virtual Switch", "label": "Porch Light"}]
        _server, port = _start_server(self, body=json.dumps(devices).encode())
        result = MakerApiClient(_config(port)).list_devices()
        self.assertEqual(result, devices)

    def test_sends_the_token_and_app_id_in_the_url(self):
        """The request carries the app id in the path and the token as a query."""
        server, port = _start_server(self, body=b"[]")
        MakerApiClient(_config(port)).list_devices()
        path = server.received[0]  # type: ignore[attr-defined]
        self.assertIn("/apps/api/42/devices", path)
        self.assertIn(f"access_token={_TOKEN}", path)

    def test_error_envelope_on_http_200_is_still_an_error(self):
        """A truthy error key is caught even though the status says success."""
        body = json.dumps({"error": True, "message": "no such device"}).encode()
        _server, port = _start_server(self, status=200, body=body)
        with self.assertRaises(MakerApiError) as caught:
            MakerApiClient(_config(port)).list_devices()
        self.assertIn("no such device", str(caught.exception))

    def test_oversized_body_is_refused(self):
        """A body past the 2 MiB cap is refused rather than parsed."""
        oversized = b'["' + b"x" * (2 * 1024 * 1024) + b'"]'
        _server, port = _start_server(self, body=oversized)
        with self.assertRaises(MakerApiError) as caught:
            MakerApiClient(_config(port)).list_devices()
        self.assertIn("exceeded", str(caught.exception))

    def test_large_but_permitted_body_still_parses(self):
        """A body just under the cap succeeds, proving the cap does not over-trigger."""
        payload = ["x" * 1000 for _ in range(1000)]  # ~1 MiB serialized
        _server, port = _start_server(self, body=json.dumps(payload).encode())
        result = MakerApiClient(_config(port)).list_devices()
        self.assertEqual(len(result), 1000)

    def test_non_json_body_is_reported_as_unavailable(self):
        """An HTML error page from the wrong app id is a clear failure, not a crash."""
        _server, port = _start_server(self, body=b"<html>Not Found</html>")
        with self.assertRaises(MakerApiUnavailableError):
            MakerApiClient(_config(port)).list_devices()

    def test_token_never_appears_in_an_error_message(self):
        """Errors name the path, never the URL, so the token stays out of logs."""
        _server, port = _start_server(self, status=500, body=b"")
        with self.assertRaises(MakerApiError) as caught:
            MakerApiClient(_config(port)).list_devices()
        self.assertNotIn(_TOKEN, str(caught.exception))


class RedirectTests(unittest.TestCase):
    def test_redirect_is_refused_and_the_target_receives_nothing(self):
        """A 302 is refused, and the redirect target never sees the credential.

        The redirect preserves the query string, which is what a real
        query-preserving redirector does and what makes a followed redirect a
        credential leak rather than a mere detour.

        The wire assertion runs outside any assertRaises, because a test shaped
        as `with assertRaises(...): call()` would report "no error raised" if
        the guard were removed — failing for a reason that says nothing about
        where the token went.
        """
        sink, sink_port = _start_server(self, body=b"[]")
        _hub, hub_port = _start_server(
            self,
            status=302,
            body=b"",
            headers={"Location": f"http://127.0.0.1:{sink_port}/stolen?access_token={_TOKEN}"},
        )

        error: Exception | None = None
        try:
            MakerApiClient(_config(hub_port)).list_devices()
        except MakerApiUnavailableError as caught:
            error = caught

        self.assertEqual(
            sink.received,  # type: ignore[attr-defined]
            [],
            "the redirect target received a request, so the access token was forwarded "
            "off-host and an attacker-chosen body was accepted as hub data",
        )
        self.assertIsNotNone(error, "the redirect was not reported as an error")
        self.assertIn("redirected", str(error))


class ProxyTests(unittest.TestCase):
    def test_a_proxy_environment_variable_cannot_divert_the_token(self):
        """http_proxy is ignored, so the token still goes only to the hub.

        urllib seeds a ProxyHandler from the inherited environment by default.
        Left alone, one variable would send the token-bearing URL to another
        host in cleartext, bypassing the private-address check entirely.
        """
        proxy, proxy_port = _start_server(self, body=b"[]")
        hub, hub_port = _start_server(self, body=b'[{"id": "1"}]')

        with mock.patch.dict(
            "os.environ",
            {
                "http_proxy": f"http://127.0.0.1:{proxy_port}",
                "HTTP_PROXY": f"http://127.0.0.1:{proxy_port}",
                "ALL_PROXY": f"http://127.0.0.1:{proxy_port}",
            },
            clear=False,
        ):
            result = MakerApiClient(_config(hub_port)).list_devices()

        self.assertEqual(
            proxy.received,  # type: ignore[attr-defined]
            [],
            "the proxy received the request, so the access token was sent off-host",
        )
        self.assertEqual(len(hub.received), 1)  # type: ignore[attr-defined]
        self.assertEqual(result, [{"id": "1"}])


class ValidationTests(unittest.TestCase):
    def test_non_ascii_digit_device_id_is_refused(self):
        """A Unicode digit is refused rather than reaching the hub as garbage."""
        client = MakerApiClient(_config(1))
        with self.assertRaises(MakerApiError):
            client.get_device("15²")

    def test_path_traversal_in_device_id_is_refused(self):
        """A device id cannot carry extra path segments."""
        client = MakerApiClient(_config(1))
        with self.assertRaises(MakerApiError):
            client.get_device("154/../../modes/2")

    def test_command_argument_accepts_a_normal_value(self):
        """A dimmer level passes, proving the filter permits legitimate input."""
        self.assertEqual(validate_command_argument("50"), "50")

    def test_command_argument_refuses_a_comma(self):
        """A comma is refused: the hub splits an argument segment on it.

        Percent-encoding does not help — Hubitat splits after decoding — so one
        argument carrying a comma would arrive at the device as several.
        """
        with self.assertRaises(MakerApiError):
            validate_command_argument("50,999")

    def test_command_argument_refuses_url_delimiters(self):
        """A slash is refused, because the hub splits the path on it."""
        with self.assertRaises(MakerApiError):
            validate_command_argument("50/off")

    def test_command_argument_refuses_control_characters(self):
        """A newline is refused, so a value cannot forge a log line."""
        with self.assertRaises(MakerApiError):
            validate_command_argument("50\nINFO fake log entry")

    def test_command_argument_refuses_an_overlong_value(self):
        """An argument past 128 characters is refused rather than sent."""
        with self.assertRaises(MakerApiError):
            validate_command_argument("5" * 129)


if __name__ == "__main__":
    unittest.main()
