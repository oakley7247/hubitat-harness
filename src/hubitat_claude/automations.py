# =============================================================================
# automations.py — HTTP client for the Claude Automations app on the hub.
#
# Part of: hubitat-claude MCP server. Called by: server.py. Calls: the parent
# app's local OAuth endpoints, through http_client.py.
# Security: this client writes rules, which are standing unattended commands —
# so it is deliberately thin. It validates the shape and size of what it sends
# and refuses ids that are not numeric, but it makes no safety judgement of its
# own: the hub is the authority on what a rule may touch, because the hub is
# what will still be enforcing it months from now. The token is separate from
# the Maker API's, rides in the query string as the hub requires, and appears
# in no exception this module raises.
# =============================================================================
"""Create, read, change, and delete rules in the hub's Claude Automations app."""

import json
import re
import urllib.parse
from typing import Any

from .config import HubitatConfig
from .http_client import BoundedHttpClient, HttpAuthError, HttpError, HttpUnavailableError

# Rule ids are hub-assigned installed-app ids: integers.
_RULE_ID_PATTERN = re.compile(r"\A[0-9]{1,12}\Z")

# Ceiling on a submitted rule. The hub caps actions and conditions itself; this
# bounds the bytes before they leave, so a malformed spec is refused here
# rather than filling the hub's request buffer.
_MAX_SPEC_BYTES = 16 * 1024

# The rule schema nests four levels at most (spec, actions, action, args). This
# bounds the walk in collect_device_ids, which runs before the size check.
_MAX_SPEC_DEPTH = 12


class AutomationsError(Exception):
    """A call to the Claude Automations app did not produce a usable result."""


class AutomationsNotConfiguredError(AutomationsError):
    """The rules app's app id and token are not set."""


class AutomationsAuthError(AutomationsError):
    """The hub rejected the automations token, or the app id does not exist."""


class AutomationsUnavailableError(AutomationsError):
    """The app could not be reached, or answered too slowly."""


class AutomationsClient:
    """Talks to one hub's Claude Automations app over the local network."""

    def __init__(self, config: HubitatConfig) -> None:
        """Build a client bound to one hub's rules app.

        Args:
            config: Validated hub connection settings.

        Raises:
            AutomationsNotConfiguredError: The rules app is not configured.
        """
        if config.automations_app_id is None or config.automations_token is None:
            raise AutomationsNotConfiguredError(
                "The rules app is not configured. Install Claude Automations on "
                "the hub, then set HUBITAT_AUTOMATIONS_APP_ID and "
                "HUBITAT_AUTOMATIONS_TOKEN in .env and restart this server."
            )
        self._config = config
        self._app_id = config.automations_app_id
        self._token = config.automations_token
        self._http = BoundedHttpClient(config.timeout_seconds)

    def _url(self, *segments: str) -> str:
        """Build a request URL for the rules app.

        Args:
            *segments: Already-validated path segments after the app id.

        Returns:
            The full URL, carrying the access token in its query string.
        """
        path = "/".join(
            ["apps", "api", self._app_id, *(urllib.parse.quote(s, safe="") for s in segments)]
        )
        query = urllib.parse.urlencode({"access_token": self._token})
        # An IPv6 literal needs brackets to be a valid authority component.
        host = self._config.host_ip
        authority = f"[{host}]" if ":" in host else host
        return f"http://{authority}:{self._config.port}/{path}?{query}"

    def _call(self, *segments: str, method: str = "GET", body: Any = None) -> Any:
        """Perform one call to the rules app and return its parsed body.

        Args:
            *segments: Path segments after the app id.
            method: The HTTP method.
            body: A JSON-serializable body, or None.

        Returns:
            The parsed response body.

        Raises:
            AutomationsAuthError: The hub rejected the token or app id.
            AutomationsUnavailableError: The app was unreachable or slow.
            AutomationsError: The app refused the request, and its refusal is
                carried through with the reasons it gave.
        """
        safe_label = "/".join(segments)
        # NOTE: the URL holds the token. It goes to the transport and out of
        # scope; `safe_label` is what any error message names.
        try:
            # The app's own 4xx bodies carry the validation problems, which are
            # exactly what the model needs to fix a refused rule — so they are
            # read. http_client still refuses to read a 401 or 403 body, where
            # Hubitat's OAuth layer echoes the submitted token.
            status, payload = self._http.request_json(
                self._url(*segments),
                safe_label=safe_label,
                method=method,
                body=body,
                read_error_body=True,
            )
        except HttpAuthError as error:
            raise AutomationsAuthError(
                "The hub rejected the automations token or app id. Re-check "
                "HUBITAT_AUTOMATIONS_APP_ID and HUBITAT_AUTOMATIONS_TOKEN "
                "against the Claude Automations app on the hub."
            ) from error
        except HttpUnavailableError as error:
            raise AutomationsUnavailableError(str(error)) from error
        except HttpError as error:
            raise AutomationsError(str(error)) from error

        if status >= 400:
            raise AutomationsError(_refusal_text(status, payload))
        return payload

    @staticmethod
    def _checked_rule_id(rule_id: str) -> str:
        """Return a rule id that is safe to place in a URL path.

        Args:
            rule_id: The hub's installed-app id for the rule.

        Returns:
            The unchanged id.

        Raises:
            AutomationsError: The id is not numeric.
        """
        if not isinstance(rule_id, str) or not _RULE_ID_PATTERN.match(rule_id):
            raise AutomationsError(f"Invalid rule id: {rule_id!r}")
        return rule_id

    @staticmethod
    def _checked_spec(spec: Any) -> dict[str, Any]:
        """Return a rule spec that is worth sending to the hub.

        Args:
            spec: The rule spec as the model supplied it.

        Returns:
            The unchanged spec.

        Raises:
            AutomationsError: The spec is not a JSON object, holds values that
                cannot be serialized, or exceeds the size cap.
        """
        if not isinstance(spec, dict):
            raise AutomationsError("A rule spec must be a JSON object.")
        try:
            size = len(json.dumps(spec))
        except (TypeError, ValueError) as error:
            raise AutomationsError("The rule spec could not be serialized as JSON.") from error
        if size > _MAX_SPEC_BYTES:
            raise AutomationsError(
                f"The rule spec is {size} bytes; the limit is {_MAX_SPEC_BYTES}."
            )
        return spec

    def list_rules(self) -> Any:
        """Return every rule the app holds, without spec detail.

        Returns:
            A dict carrying `rules` and the app's current safety state.
        """
        return self._call("rules")

    def get_rule(self, rule_id: str) -> Any:
        """Return one rule with its full spec.

        Args:
            rule_id: The rule's id, as shown by list_rules.

        Returns:
            The rule and its spec.
        """
        return self._call("rules", self._checked_rule_id(rule_id))

    def list_pool(self) -> Any:
        """Return the devices rules may use, with their attributes and commands.

        Returns:
            A dict carrying `devices` and the hub's mode names.
        """
        return self._call("pool")

    def create_rule(self, spec: dict[str, Any]) -> Any:
        """Create one rule.

        Args:
            spec: The rule spec.

        Returns:
            The created rule's id, name, and enabled state.
        """
        return self._call("rules", method="POST", body=self._checked_spec(spec))

    def update_rule(self, rule_id: str, spec: dict[str, Any]) -> Any:
        """Replace one rule's spec.

        Args:
            rule_id: The rule's id.
            spec: The replacement spec, complete rather than partial.

        Returns:
            The rule's id, name, and enabled state.
        """
        return self._call(
            "rules", self._checked_rule_id(rule_id), method="PUT", body=self._checked_spec(spec)
        )

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> Any:
        """Enable or disable one rule without deleting it.

        Args:
            rule_id: The rule's id.
            enabled: Whether the rule should act.

        Returns:
            The rule's id, name, and new enabled state.
        """
        return self._call(
            "rules",
            self._checked_rule_id(rule_id),
            "enabled",
            method="PUT",
            body={"enabled": bool(enabled)},
        )

    def delete_rule(self, rule_id: str) -> Any:
        """Delete one rule and everything it scheduled.

        Args:
            rule_id: The rule's id.

        Returns:
            A dict confirming the deletion and naming the rule.
        """
        return self._call("rules", self._checked_rule_id(rule_id), method="DELETE")


def _refusal_text(status: int, payload: Any) -> str:
    """Turn the app's refusal into one message the model can act on.

    Args:
        status: The HTTP status the app returned.
        payload: The parsed refusal body, if it sent one.

    Returns:
        The app's own reasons where it gave them, otherwise the status.
    """
    if isinstance(payload, dict):
        reason = str(payload.get("error") or f"The hub returned HTTP {status}.")
        problems = payload.get("problems")
        if isinstance(problems, list) and problems:
            # These are the validator's own messages, naming the field that
            # failed and what the hub reports instead — which is what lets a
            # refused rule be corrected rather than guessed at again.
            listed = "; ".join(str(problem) for problem in problems[:20])
            return f"{reason} {listed}"
        return reason
    return f"The hub returned HTTP {status}."


def collect_device_ids(spec: Any, depth: int = 0) -> set[str]:
    """Return every device id a rule spec names, at any depth.

    Args:
        spec: A rule spec, or any part of one.
        depth: Current recursion depth, counted internally.

    Returns:
        The set of device ids found, as strings.
    """
    # SECURITY: used to hold a rule to HUBITAT_WRITABLE_DEVICE_IDS. The walk is
    # over every nested value rather than the three keys the schema defines
    # today, so a spec shape added later cannot slip a device past the check by
    # putting its id somewhere this function was never taught about.
    #
    # SECURITY: the depth bound matters because this runs before the size check
    # in _checked_spec — a deeply nested spec would otherwise raise
    # RecursionError here, which is not an AutomationsError and so would escape
    # as a crash rather than a refusal. Stopping short is safe: the caller
    # treats an unwalkable spec as one it cannot clear, and _MAX_SPEC_DEPTH is
    # far past anything the schema produces.
    if depth >= _MAX_SPEC_DEPTH:
        raise AutomationsError(
            f"The rule spec nests deeper than {_MAX_SPEC_DEPTH} levels and was refused."
        )
    found: set[str] = set()
    if isinstance(spec, dict):
        for key, value in spec.items():
            if key == "deviceId" and isinstance(value, (str, int)):
                found.add(str(value))
            else:
                found |= collect_device_ids(value, depth + 1)
    elif isinstance(spec, list):
        for entry in spec:
            found |= collect_device_ids(entry, depth + 1)
    return found
