# =============================================================================
# http_client.py — the HTTP transport both hub clients share.
#
# Part of: hubitat-claude MCP server. Called by: maker_api.py and
# automations.py. Calls: one private IP on the local network.
# Security: this module holds the properties that must not drift between the
# two callers — proxies are suppressed, redirects are refused, response bodies
# are bounded by both size and wall clock, and no exception raised here carries
# the URL, which holds the access token in its query string. Extracted rather
# than copied for exactly that reason: two versions of this logic would mean
# two chances for one of them to lose a control.
# =============================================================================
"""Bounded, proxy-free, redirect-free HTTP for talking to a Hubitat hub."""

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

# A hub with several hundred devices answers in well under 1 MiB. The cap
# bounds the bytes read from the socket, which in turn bounds the work
# json.loads can be asked to do. Above it the read is refused rather than
# truncated, because a truncated JSON document parses as an error anyway.
MAX_RESPONSE_BYTES = 2 * 1024 * 1024

# Read granularity. An upper bound per iteration, not a demand: the loop uses
# read1, which returns whatever has arrived rather than waiting for the full
# amount.
_READ_CHUNK_BYTES = 64 * 1024

# SECURITY: statuses whose bodies are never read. Hubitat echoes a rejected
# token back inside its 401 document — observed against a real hub on
# 2026-08-03 — so an authentication failure is itself a credential. Reading it
# would put the token one careless log line away from disclosure.
_NEVER_READ_BODY = frozenset({401, 403})


class HttpError(Exception):
    """An HTTP call to the hub did not produce a usable result."""


class HttpAuthError(HttpError):
    """The hub rejected the access token, or the app id does not exist."""


class HttpUnavailableError(HttpError):
    """The hub could not be reached, redirected, or answered too slowly."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect instead of following it."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        """Return None so urllib raises rather than following the redirect."""
        # SECURITY: the access token travels in the query string, so following
        # a 3xx would re-send that credential to whatever host the Location
        # header names. A machine-to-machine call to a known LAN address has no
        # legitimate reason to redirect, so a 3xx is an error (ledger LL-14).
        return None


class BoundedHttpClient:
    """Performs one hub HTTP call under a size cap and a wall-clock deadline."""

    def __init__(self, timeout_seconds: float) -> None:
        """Build a client with a fixed per-request timeout.

        Args:
            timeout_seconds: Connect and read timeout for every call.
        """
        self._timeout_seconds = timeout_seconds
        # SECURITY: the empty ProxyHandler suppresses urllib's default, which
        # seeds itself from http_proxy/HTTP_PROXY/ALL_PROXY in the inherited
        # environment. Without it, one environment variable would route the
        # token-bearing URL to an arbitrary host in cleartext — bypassing the
        # private-address check and the pinned literal entirely. A call to a
        # known LAN address has no reason to traverse a proxy.
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirectHandler
        )

    def request_json(
        self,
        url: str,
        *,
        safe_label: str,
        method: str = "GET",
        body: Any = None,
        read_error_body: bool = False,
    ) -> tuple[int, Any]:
        """Perform one request and return its status and parsed body.

        Args:
            url: The full request URL. Holds the access token; never logged.
            safe_label: A token-free description of the request, used in every
                error message this method raises.
            method: The HTTP method.
            body: A JSON-serializable body, or None.
            read_error_body: Whether to parse the body of a 4xx response.
                True only for endpoints whose error documents this project
                writes itself; never for the hub's own error pages.

        Returns:
            A tuple of the HTTP status and the parsed JSON body. The body is
            None when the response carried none.

        Raises:
            HttpAuthError: The hub returned 401 or 403.
            HttpUnavailableError: The hub was unreachable, timed out,
                redirected, or returned a body that was not usable JSON.
            HttpError: The response exceeded the size cap, or the status was
                an error this caller did not ask to read.
        """
        encoded = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(url, data=encoded, method=method)
        if encoded is not None:
            request.add_header("Content-Type", "application/json")

        try:
            with self._opener.open(request, timeout=self._timeout_seconds) as response:
                raw = self._read_bounded(response, safe_label)
                status = int(response.status)
        except urllib.error.HTTPError as error:
            return self._handle_http_error(error, safe_label, read_error_body)
        except urllib.error.URLError as error:
            raise HttpUnavailableError(f"Could not reach the hub: {error.reason}") from error
        except TimeoutError as error:
            raise HttpUnavailableError(
                f"The hub did not answer within {self._timeout_seconds} seconds."
            ) from error

        if len(raw) > MAX_RESPONSE_BYTES:
            raise HttpError(
                f"The hub's response to /{safe_label} exceeded "
                f"{MAX_RESPONSE_BYTES} bytes and was refused."
            )
        return status, self._parse(raw, safe_label)

    def _handle_http_error(
        self, error: urllib.error.HTTPError, safe_label: str, read_error_body: bool
    ) -> tuple[int, Any]:
        """Turn an HTTPError into either a returned response or an exception.

        Args:
            error: The raised HTTPError.
            safe_label: A token-free description of the request.
            read_error_body: Whether the caller wants 4xx bodies parsed.

        Returns:
            The status and parsed body, when the caller asked for it and the
            status is one whose body is safe to read.

        Raises:
            HttpAuthError: The status was 401 or 403.
            HttpUnavailableError: The hub redirected.
            HttpError: Any other status the caller did not ask to read.
        """
        if error.code in _NEVER_READ_BODY:
            # HTTPError holds an open socket. Closing it unread is the point:
            # this body carries the submitted token.
            error.close()
            raise HttpAuthError(
                "The hub rejected the access token or the app id. Re-check the "
                "app id and token against the app on the hub."
            ) from error
        if error.code in (301, 302, 303, 307, 308):
            error.close()
            raise HttpUnavailableError(
                f"The hub redirected the request for /{safe_label}. Refused: "
                "following it would send the access token to another host."
            ) from error
        if read_error_body:
            # HTTPError is itself a response object holding an open socket, so
            # it is closed here rather than left to the garbage collector.
            try:
                raw = self._read_bounded(error, safe_label)
            finally:
                error.close()
            return error.code, self._parse(raw, safe_label)
        error.close()
        raise HttpError(f"The hub returned HTTP {error.code} for /{safe_label}.") from error

    @staticmethod
    def _parse(raw: bytes, safe_label: str) -> Any:
        """Parse a response body as JSON.

        Args:
            raw: The body bytes.
            safe_label: A token-free description of the request.

        Returns:
            The parsed body, or None when the body was empty.

        Raises:
            HttpUnavailableError: The body was not valid UTF-8 JSON.
        """
        if not raw.strip():
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
            raise HttpUnavailableError(
                f"The hub's response to /{safe_label} was not valid JSON. This "
                "usually means the app id belongs to a different app than the "
                "one expected."
            ) from error

    def _read_bounded(self, response: Any, safe_label: str) -> bytes:
        """Read a response body under both a size cap and a wall-clock deadline.

        Args:
            response: The open HTTP response.
            safe_label: The token-free request label, for error messages.

        Returns:
            The body, up to one byte past the cap so an over-large body is
            detectable rather than silently truncated into invalid JSON.

        Raises:
            HttpUnavailableError: The hub was still sending after the timeout
                had elapsed across the whole read.
        """
        # SECURITY: the socket timeout applies per read *operation*, and it
        # resets on every byte received. A between-reads deadline check alone
        # is therefore not a bound: `read(n)` blocks until n bytes arrive, so a
        # peer trickling one byte just inside each window keeps a single call
        # blocked far past the deadline, which is never re-evaluated. Two
        # things make the bound real. The socket's own timeout is tightened to
        # whatever budget is left before each read, so a stalled read raises
        # rather than waiting; and the chunk is small, which caps how much a
        # single blocking call can be asked to wait for if the socket cannot be
        # reached to tighten.
        # SECURITY: read1 rather than read. `read(n)` blocks until it has all n
        # bytes, so a peer dribbling data stays inside one call indefinitely and
        # the loop's deadline check never runs — the bound would exist on paper
        # and not in fact. read1 returns as soon as any data is available, which
        # is what lets the check below actually fire. Falling back to read keeps
        # a response object that lacks read1 working, at the cost of the
        # tightened socket timeout being the only bound.
        read = getattr(response, "read1", None) or response.read

        deadline = time.monotonic() + self._timeout_seconds
        remaining = MAX_RESPONSE_BYTES + 1
        chunks: list[bytes] = []
        while remaining > 0:
            left = deadline - time.monotonic()
            if left <= 0:
                raise HttpUnavailableError(
                    f"The hub was still sending a response for /{safe_label} after "
                    f"{self._timeout_seconds} seconds."
                )
            self._tighten_socket_timeout(response, left)
            try:
                chunk = read(min(_READ_CHUNK_BYTES, remaining))
            except TimeoutError as error:
                raise HttpUnavailableError(
                    f"The hub stalled partway through its response for /{safe_label}."
                ) from error
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    @staticmethod
    def _tighten_socket_timeout(response: Any, seconds: float) -> None:
        """Lower the underlying socket's timeout to the time budget left.

        Args:
            response: The open HTTP response.
            seconds: Remaining budget; the socket will not wait longer.
        """
        # NOTE: urllib exposes no public way to adjust the timeout mid-response,
        # so this reaches through http.client's buffered reader to the socket.
        # It is best effort by design — the private chain can be absent on a
        # wrapped or mocked response, and the small chunk size above is what
        # keeps the bound meaningful when that happens.
        sock = getattr(getattr(response, "fp", None), "raw", None)
        sock = getattr(sock, "_sock", None)
        if sock is None:
            return
        try:
            sock.settimeout(max(0.05, seconds))
        except OSError:
            # A closed or detached socket needs no timeout; the read that
            # follows will fail on its own and be reported by the caller.
            return
