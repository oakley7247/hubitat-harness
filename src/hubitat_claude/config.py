# =============================================================================
# config.py — reads and validates the Hubitat hub connection settings.
#
# Part of: hubitat-claude MCP server. Called by: server.py at startup.
# Security: the Maker API token is a full-control credential for the home. It
# is read from the environment only (never from code or argv, where it would
# land in shell history and `ps` output), and never appears in any error this
# module raises. The hub address is pinned to a validated private IP literal —
# see the SECURITY note at _resolve_private_ip for why that matters.
# =============================================================================
"""Load and validate the Hubitat Maker API connection settings from the environment."""

import ipaddress
import os
import re
import socket
from dataclasses import dataclass

# The Maker API app id is a hub-assigned integer; the token is a UUID the hub
# mints. Both ride in a URL, so both are pattern-checked before first use
# rather than trusted to be well-formed (see LL-2: validate, then store what
# was validated).
_APP_ID_PATTERN = re.compile(r"\A[0-9]{1,12}\Z")
_TOKEN_PATTERN = re.compile(r"\A[0-9a-fA-F-]{8,64}\Z")

_DEFAULT_TIMEOUT_SECONDS = 10.0
_MIN_TIMEOUT_SECONDS = 1.0
_MAX_TIMEOUT_SECONDS = 60.0

# A Hubitat hub serves the Maker API on port 80. The setting exists for hubs
# reached through a local reverse proxy, and so the HTTP client can be tested
# against a loopback server on an ephemeral port.
_DEFAULT_PORT = 80


class ConfigError(Exception):
    """Raised when the environment does not describe a usable hub connection."""


@dataclass(frozen=True)
class HubitatConfig:
    """Validated settings for reaching one Hubitat hub's Maker API instance.

    Attributes:
        host_ip: The hub's address as a private IP literal, already resolved
            and range-checked. Requests connect to this, never to the
            hostname the operator typed.
        port: The hub's HTTP port, 80 unless overridden.
        app_id: The Maker API installed-app id, digits only.
        access_token: The Maker API access token. Never log this.
        timeout_seconds: Per-request connect/read timeout.
        allow_security_commands: Whether commands to locks, garage doors,
            valves, keypads, and alarms — plus hub mode changes — are
            permitted. Defaults to False.
    """

    host_ip: str
    port: int
    app_id: str
    access_token: str
    timeout_seconds: float
    allow_security_commands: bool


def _require_env(name: str) -> str:
    """Return a required environment variable, or raise ConfigError naming it.

    Args:
        name: The environment variable to read.

    Returns:
        The variable's value with surrounding whitespace stripped.

    Raises:
        ConfigError: The variable is unset or empty.
    """
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(
            f"{name} is not set. Copy .env.example to .env and fill it in, "
            "or export the variable before starting the server."
        )
    return value


def _resolve_private_ip(host: str) -> str:
    """Resolve a hub address and confirm every answer is a private address.

    Args:
        host: An IP literal or hostname naming the hub on the local network.

    Returns:
        The resolved address as an IP literal, to be used in place of `host`.

    Raises:
        ConfigError: The name does not resolve, or any resolved address is
            globally routable.
    """
    # SECURITY: this integration is LAN-only by design, and the Maker API
    # carries its token in the query string over plain HTTP. A hub address
    # pointing off the local network would hand that token to a stranger, so a
    # globally routable answer is refused rather than warned about. Checking
    # `is_global` uses the platform's own predicate instead of a hand-written
    # range list, which would date and miss reserved blocks.
    try:
        resolved = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as error:
        raise ConfigError(
            f"HUBITAT_HOST {host!r} does not resolve: {error.strerror or error}"
        ) from error

    # getaddrinfo's sockaddr is typed as a union; the first element is the
    # address string for every family this code accepts.
    addresses = {str(entry[4][0]) for entry in resolved}
    if not addresses:
        raise ConfigError(f"HUBITAT_HOST {host!r} resolved to no addresses.")

    for address in sorted(addresses):
        # A scope suffix (fe80::1%en0) is not part of the address itself.
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
        if parsed.is_global:
            raise ConfigError(
                f"HUBITAT_HOST {host!r} resolves to the public address {address}. "
                "This server only talks to a hub on the local network, because "
                "the Maker API sends its token in cleartext."
            )

    # SECURITY: returning the resolved literal — rather than the hostname —
    # means the address checked above is the address connected to. A later DNS
    # answer cannot redirect the credential somewhere else.
    return sorted(addresses)[0]


def _load_timeout() -> float:
    """Return the configured per-request timeout in seconds.

    Returns:
        The timeout, defaulting to 10 seconds when unset.

    Raises:
        ConfigError: The value is not a number, or falls outside 1-60 seconds.
    """
    raw = os.environ.get("HUBITAT_TIMEOUT_SECONDS", "").strip()
    if not raw:
        return _DEFAULT_TIMEOUT_SECONDS
    try:
        timeout = float(raw)
    except ValueError as error:
        raise ConfigError(f"HUBITAT_TIMEOUT_SECONDS must be a number, got {raw!r}.") from error
    if not _MIN_TIMEOUT_SECONDS <= timeout <= _MAX_TIMEOUT_SECONDS:
        raise ConfigError(
            "HUBITAT_TIMEOUT_SECONDS must be between "
            f"{_MIN_TIMEOUT_SECONDS} and {_MAX_TIMEOUT_SECONDS}, got {timeout}."
        )
    return timeout


def _load_port() -> int:
    """Return the hub's HTTP port.

    Returns:
        The port, defaulting to 80 when unset.

    Raises:
        ConfigError: The value is not an integer in the range 1-65535.
    """
    raw = os.environ.get("HUBITAT_PORT", "").strip()
    if not raw:
        return _DEFAULT_PORT
    # A bare int() would accept non-ASCII digits and surrounding signs; the
    # explicit ASCII-digit check keeps the accepted set to what a port is.
    if not (raw.isascii() and raw.isdigit()):
        raise ConfigError(f"HUBITAT_PORT must be a whole number, got {raw!r}.")
    port = int(raw)
    if not 1 <= port <= 65535:
        raise ConfigError(f"HUBITAT_PORT must be between 1 and 65535, got {port}.")
    return port


def _load_flag(name: str) -> bool:
    """Return a boolean environment flag, defaulting to False.

    Args:
        name: The environment variable to read.

    Returns:
        True only for the exact values "true", "1", "yes", or "on".

    Raises:
        ConfigError: The value is set but is not a recognized boolean.
    """
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return False
    if raw in {"true", "1", "yes", "on"}:
        return True
    if raw in {"false", "0", "no", "off"}:
        return False
    raise ConfigError(
        f"{name} must be true or false, got {raw!r}. "
        "An unrecognized value is refused rather than guessed at, because "
        "this flag controls whether locks and alarms can be commanded."
    )


def load_config() -> HubitatConfig:
    """Build a validated HubitatConfig from the process environment.

    Returns:
        The validated settings.

    Raises:
        ConfigError: Any required variable is missing or any value is invalid.
            The message names the variable and never echoes the token.
    """
    host = _require_env("HUBITAT_HOST")
    app_id = _require_env("HUBITAT_MAKER_APP_ID")
    access_token = _require_env("HUBITAT_MAKER_TOKEN")

    if not _APP_ID_PATTERN.match(app_id):
        raise ConfigError(
            f"HUBITAT_MAKER_APP_ID must be digits only, got {app_id!r}. "
            "Find it in the Maker API app's URL on the hub."
        )
    if not _TOKEN_PATTERN.match(access_token):
        # NOTE: the token itself is deliberately absent from this message —
        # config errors are printed and often pasted into chats and issues.
        raise ConfigError(
            "HUBITAT_MAKER_TOKEN does not look like a Maker API token "
            "(expected 8-64 hex characters and dashes). Value withheld from "
            "this message; re-copy it from the Maker API app on the hub."
        )

    return HubitatConfig(
        host_ip=_resolve_private_ip(host),
        port=_load_port(),
        app_id=app_id,
        access_token=access_token,
        timeout_seconds=_load_timeout(),
        allow_security_commands=_load_flag("HUBITAT_ALLOW_SECURITY_COMMANDS"),
    )
