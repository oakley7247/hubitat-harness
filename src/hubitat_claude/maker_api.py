# =============================================================================
# maker_api.py — HTTP client for one Hubitat hub's local Maker API.
#
# Part of: hubitat-claude MCP server. Called by: server.py. Calls: the hub over
# plain HTTP on the local network (the Maker API serves HTTP and authenticates
# by query-string token; it offers no header auth and no trusted certificate).
# Security: redirects are refused so the token cannot be forwarded to another
# host; every path segment is validated against a strict pattern before it is
# interpolated into a URL; response bodies are size-capped before parsing; and
# no exception raised here contains the token or the full URL.
# =============================================================================
"""Call the Hubitat Maker API and return parsed, size-bounded JSON."""

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .config import HubitatConfig

# --- Input patterns ----------------------------------------------------------

# Device ids are hub-assigned integers. An explicit ASCII-digit pattern is used
# rather than str.isdigit(), which accepts non-ASCII digits like '²' and
# would push a value the hub cannot parse into the URL (ledger LL-3).
_DEVICE_ID_PATTERN = re.compile(r"\A[0-9]{1,12}\Z")
_MODE_ID_PATTERN = re.compile(r"\A[0-9]{1,12}\Z")
# Hubitat command names are Groovy method names: letters, then alphanumerics.
_COMMAND_PATTERN = re.compile(r"\A[A-Za-z][A-Za-z0-9]{0,63}\Z")
# Command arguments are printable ASCII without the delimiters that would
# change the URL's shape. Control characters are excluded so a value cannot
# forge a log line downstream (ledger LL-2).
_ARGUMENT_PATTERN = re.compile(r"\A[ -~]{1,128}\Z")
_ARGUMENT_FORBIDDEN = frozenset("/?#&%")

# --- Bounds ------------------------------------------------------------------

# A hub with several hundred devices answers /devices in well under 1 MiB.
# This cap bounds the bytes read from the socket, which in turn bounds the work
# json.loads can be asked to do — the two layers that turn a hub response into
# memory in this process. Above the cap the read is refused rather than
# truncated, because a truncated JSON document parses as an error anyway.
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class MakerApiError(Exception):
    """A Maker API call did not produce a usable result."""


class MakerApiAuthError(MakerApiError):
    """The hub rejected the access token, or the app id does not exist."""


class MakerApiUnavailableError(MakerApiError):
    """The hub could not be reached, or answered too slowly."""


def _validated_segment(value: str, pattern: re.Pattern[str], label: str) -> str:
    """Return `value` if it matches `pattern`, else raise MakerApiError.

    Args:
        value: The caller-supplied path segment.
        pattern: The pattern the segment must match in full.
        label: Human-readable name of the field, used in the error message.

    Returns:
        The unchanged value, safe to place in a URL path.

    Raises:
        MakerApiError: The value does not match.
    """
    # SECURITY: this is the only gate between a tool argument and a URL path
    # segment. It runs before quoting rather than relying on quoting alone, so
    # an unexpected shape is refused loudly instead of silently encoded into a
    # request the hub will misinterpret.
    if not isinstance(value, str) or not pattern.match(value):
        raise MakerApiError(f"Invalid {label}: {value!r}")
    return value


def validate_command_argument(argument: str) -> str:
    """Return a command argument that is safe to send as a URL path segment.

    Args:
        argument: The value to pass to a device command, such as a dimmer level.

    Returns:
        The unchanged argument.

    Raises:
        MakerApiError: The argument is empty, over 128 characters, contains a
            control character, or contains a URL delimiter.
    """
    _validated_segment(argument, _ARGUMENT_PATTERN, "command argument")
    # SECURITY: Maker API passes command arguments as path segments and splits
    # multiple arguments on commas. Percent-encoding would hide these from the
    # URL parser but not from the hub's own splitting, so the delimiters are
    # rejected outright rather than escaped (ledger LL-9: neutralize the
    # downstream grammar, do not trust a general-purpose encoder to know it).
    if any(character in _ARGUMENT_FORBIDDEN for character in argument):
        raise MakerApiError(f"Command argument may not contain any of / ? # & % — got {argument!r}")
    return argument


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect instead of following it."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        """Return None so urllib raises rather than following the redirect."""
        # SECURITY: the access token travels in the query string, so following
        # a 3xx would re-send that credential to whatever host the Location
        # header names. A machine-to-machine call to a known LAN address has no
        # legitimate reason to redirect, so a 3xx is an error (ledger LL-14).
        return None


class MakerApiClient:
    """Talks to one Hubitat hub's Maker API over the local network."""

    def __init__(self, config: HubitatConfig) -> None:
        """Build a client bound to one hub.

        Args:
            config: Validated hub connection settings.
        """
        self._config = config
        self._opener = urllib.request.build_opener(_NoRedirectHandler)

    def _request(self, *segments: str) -> Any:
        """Perform one Maker API GET and return the parsed JSON body.

        Args:
            *segments: Already-validated path segments after the app id, such
                as ("devices", "154", "on").

        Returns:
            The parsed JSON body: a list or a dict, depending on the endpoint.

        Raises:
            MakerApiAuthError: The hub returned 401, or 403.
            MakerApiUnavailableError: The hub was unreachable, timed out,
                redirected, or returned a body that was not usable JSON.
            MakerApiError: The hub returned an error envelope or another
                non-success status.
        """
        # Every Maker API endpoint is a GET, including the ones that change
        # device state; the hub documents no POST form.
        path = "/".join(
            [
                "apps",
                "api",
                self._config.app_id,
                *(urllib.parse.quote(s, safe="") for s in segments),
            ]
        )
        query = urllib.parse.urlencode({"access_token": self._config.access_token})
        # An IPv6 literal needs brackets to be a valid authority component.
        host = self._config.host_ip
        authority = f"[{host}]" if ":" in host else host
        url = f"http://{authority}:{self._config.port}/{path}?{query}"
        # NOTE: `url` holds the token. It is passed to urlopen and then goes out
        # of scope — it is never logged, and never placed in an exception. Error
        # messages below name `segments` instead, which is token-free.
        safe_path = "/".join(segments)

        try:
            with self._opener.open(url, timeout=self._config.timeout_seconds) as response:
                # Read one byte past the cap so an over-large body is detected
                # rather than silently truncated into invalid JSON.
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                status = response.status
        except urllib.error.HTTPError as error:
            if error.code in (401, 403):
                raise MakerApiAuthError(
                    "The hub rejected the Maker API token or app id. Re-check "
                    "HUBITAT_MAKER_APP_ID and HUBITAT_MAKER_TOKEN against the "
                    "Maker API app on the hub."
                ) from error
            if error.code in (301, 302, 303, 307, 308):
                raise MakerApiUnavailableError(
                    f"The hub redirected the request for /{safe_path}. Refused: "
                    "following it would send the access token to another host."
                ) from error
            raise MakerApiError(f"The hub returned HTTP {error.code} for /{safe_path}.") from error
        except urllib.error.URLError as error:
            raise MakerApiUnavailableError(
                f"Could not reach the hub at {self._config.host_ip}: {error.reason}"
            ) from error
        except TimeoutError as error:
            raise MakerApiUnavailableError(
                f"The hub did not answer within {self._config.timeout_seconds} seconds."
            ) from error

        if len(raw) > _MAX_RESPONSE_BYTES:
            raise MakerApiError(
                f"The hub's response to /{safe_path} exceeded "
                f"{_MAX_RESPONSE_BYTES} bytes and was refused."
            )
        if status != 200:
            raise MakerApiError(f"The hub returned HTTP {status} for /{safe_path}.")

        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise MakerApiUnavailableError(
                f"The hub's response to /{safe_path} was not valid JSON. This "
                "usually means the app id belongs to something other than a "
                "Maker API instance."
            ) from error

        # NOTE: the Maker API can report failure as HTTP 200 with a truthy
        # `error` key, so the status check above is not sufficient on its own.
        if isinstance(payload, dict) and payload.get("error"):
            raise MakerApiError(
                f"The hub reported an error for /{safe_path}: "
                f"{str(payload.get('message', 'no detail given'))[:200]}"
            )
        return payload

    def list_devices(self) -> Any:
        """Return every device exposed by this Maker API instance.

        Returns:
            A list of dicts carrying `id`, `name`, and `label`.
        """
        return self._request("devices")

    def get_device(self, device_id: str) -> Any:
        """Return one device's full detail, including attributes and commands.

        Args:
            device_id: The hub's numeric device id, as a string.

        Returns:
            A dict with `id`, `label`, `capabilities`, `attributes`, `commands`.

        Raises:
            MakerApiError: The id is not numeric, or the hub refused the call.
        """
        return self._request(
            "devices", _validated_segment(device_id, _DEVICE_ID_PATTERN, "device id")
        )

    def get_device_events(self, device_id: str) -> Any:
        """Return the device's most recent events (the hub returns up to 20).

        Args:
            device_id: The hub's numeric device id, as a string.

        Returns:
            A list of event dicts with `name`, `value`, and `date`.

        Raises:
            MakerApiError: The id is not numeric, or the hub refused the call.
        """
        checked = _validated_segment(device_id, _DEVICE_ID_PATTERN, "device id")
        return self._request("devices", checked, "events")

    def send_command(self, device_id: str, command: str, argument: str | None = None) -> Any:
        """Send one command to a device.

        Args:
            device_id: The hub's numeric device id, as a string.
            command: The command name, which the caller must have already
                checked against the device's own reported command list.
            argument: Optional single argument, such as a dimmer level.

        Returns:
            The device's detail as the hub saw it at the moment of the call.

        Raises:
            MakerApiError: Any argument is malformed, or the hub refused.
        """
        checked_id = _validated_segment(device_id, _DEVICE_ID_PATTERN, "device id")
        checked_command = _validated_segment(command, _COMMAND_PATTERN, "command name")
        if argument is None:
            return self._request("devices", checked_id, checked_command)
        return self._request(
            "devices", checked_id, checked_command, validate_command_argument(argument)
        )

    def list_modes(self) -> Any:
        """Return the hub's modes and which one is active.

        Returns:
            A list of dicts carrying `id`, `name`, and `active`.
        """
        return self._request("modes")

    def set_mode(self, mode_id: str) -> Any:
        """Switch the hub to a mode.

        Args:
            mode_id: The mode's numeric id — the hub sets modes by id, not name.

        Returns:
            The hub's updated mode list.

        Raises:
            MakerApiError: The id is not numeric, or the hub refused the call.
        """
        return self._request("modes", _validated_segment(mode_id, _MODE_ID_PATTERN, "mode id"))
