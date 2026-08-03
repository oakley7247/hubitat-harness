# hubitat-claude

Connects a Hubitat Elevation hub to Claude, in both directions. An (MCP) Model Context Protocol server lets you ask Claude to check sensors and control devices; a Groovy driver lets hub automations ask Claude a question and act on the answer.

Everything stays on your local network. The server refuses any hub address that is not private, and never uses Hubitat's cloud relay.

## Install

```bash
git clone https://github.com/oakley7247/hubitat-claude.git
cd hubitat-claude
uv venv --python 3.14 .venv
uv pip install --require-hashes -r requirements.lock
uv pip install -e . --no-deps
```

## Set up the hub

1. On the hub, open **Apps → Add Built-In App → Maker API**.
2. Under **Select Devices**, choose only the devices Claude should see. Create a separate Maker API instance for this rather than reusing a broad one — the token is scoped to whatever that instance exposes.
3. Leave **Allow Access via Local IP Address** on, and leave cloud access **off**.
4. Copy the **app id** from the app's URL and the **access token** from its settings page.
5. `cp .env.example .env` and fill in `HUBITAT_HOST`, `HUBITAT_MAKER_APP_ID`, and `HUBITAT_MAKER_TOKEN`.

## Run

Register the server with Claude Code:

```bash
claude mcp add hubitat --env-file .env -- /full/path/to/hubitat-claude/.venv/bin/hubitat-claude
```

To check the wiring before registering it, run it directly — it exits immediately with the name of the first missing or invalid setting, and otherwise waits for MCP traffic on stdin:

```bash
set -a && source .env && set +a && .venv/bin/hubitat-claude
```

## Example

Once registered, ask Claude in plain language:

> Which lights are on downstairs?

> Turn the porch light down to 30%.

> Has the back door sensor reported anything in the last hour?

Claude calls `list_devices` to find the device, `get_device` to read its state and see which commands it accepts, then `send_command`. Your MCP client asks you to approve each command before it runs.

## Configuration

Every variable is documented in `.env.example`. Three are required — `HUBITAT_HOST`, `HUBITAT_MAKER_APP_ID`, `HUBITAT_MAKER_TOKEN` — and the rest have safe defaults.

One is worth understanding before you change it:

**`HUBITAT_ALLOW_SECURITY_COMMANDS`** is off by default. While it is off, the server refuses every command to a device that reports the `Lock`, `DoorControl`, `GarageDoorControl`, `Valve`, `SecurityKeypad`, or `Alarm` capability, and refuses hub mode changes as well — mode drives Hubitat Safety Monitor on most hubs, so "set mode to Home" is a disarm.

The reason for the default is that device names and sensor values flow into Claude's context, and anyone who can name a device can write text that Claude reads. Turning this on means text hidden in a device label could talk Claude into unlocking a door. Your MCP client's approval prompt is the backstop if you do turn it on.

Separately, commands named `open`, `close`, `unlock`, `arm`, `disarm` and the like are refused on **any** device while that setting is off, whatever the device claims to be — because a garage door or gate is often wired as a plain relay that reports only `Switch`.

**`HUBITAT_WRITABLE_DEVICE_IDS`** closes the gap that neither of those covers. If a door, gate, or garage opener on your hub is wired as a plain switch, it declares no lock or door capability and is opened by an ordinary `on` — so nothing above recognizes it as a boundary. Set this variable to the comma-separated ids of the devices Claude may command, and everything else becomes read-only:

```bash
HUBITAT_WRITABLE_DEVICE_IDS=154,200,7
```

Leave it unset and every device that passes the checks above is commandable. If you are unsure whether such a device exists on your hub, set the list — it costs one line and removes the question.

Setting it also turns off hub mode changes entirely. A mode is not a device and has no id, so it can never appear in the list; refusing it keeps the setting's promise honest rather than leaving one write path outside the fence.

## Troubleshooting

**`The hub rejected the Maker API token or app id`** — the hub returns HTTP 401 with `invalid_token` for a token it no longer recognizes, and it treats an expired token exactly like a junk one. Maker API tokens are invalidated when the app mints a new one, so re-opening and saving the Maker API app can retire the token you are using. Copy the current token from the app's settings page into `.env`.

To tell a bad token from a bad app id, ask the hub for an app id that cannot exist:

```bash
curl -s -o /dev/null -w '%{http_code}\n' "http://<hub-ip>/apps/api/999999/devices?access_token=x"
```

A `404` there and a `401` on your real app id means the app exists and the token is the problem. A `404` on your real app id means the app id is wrong.

**Do not paste a raw 401 body anywhere.** The hub echoes the submitted token back inside the error document (`<error_description>your-token</error_description>`), so an error response is itself a credential. This server never logs response bodies for that reason.

## The Claude Assistant driver

`drivers/claude-assistant.groovy` is a virtual device for the hub. It gives Rule Machine an `askClaude` command: pass it a question, and it publishes Claude's answer to the `lastReply` attribute, which a rule can trigger on.

To install it:

1. On the hub, open **Developer Tools → Drivers Code → New Driver**, paste the file, and **Save**.
2. Open **Devices → Add Device → Virtual**, choose type **Claude Assistant**, and save.
3. In the new device's preferences, paste your Anthropic API key from `console.anthropic.com`, then **Save Preferences**.

Then, from Rule Machine, use **Run Custom Action** on that device and call `askClaude` with your prompt.

Trigger your rules on **`lastReply`**, which only ever holds an answer. Failures go to `lastError` and set `status` to `error`, so a rule waiting for an answer never fires on an error string.

Three things bound what it can cost you, all adjustable in the device's preferences: a per-call token ceiling, a minimum gap between calls (5 seconds by default) so a misfiring rule cannot loop, and a daily call cap (100 by default).

Both counters are charged when the request goes out, never when the answer comes back, and nothing gives a charge back. That is deliberate: a timed-out or refused call is still billed, and a rule whose calls all fail is exactly the runaway the cap exists to stop — so a cap that only counted successes would go slack in the one case it is for.

The device also refuses a second question while one is still in flight, rather than accepting it and discarding one of the two answers.

Hubitat refuses to store an attribute longer than 1024 characters, so replies are capped — 500 characters by default — and the system prompt asks Claude to answer briefly.

## Development

```bash
.venv/bin/python -m unittest discover -s . -p "test_*.py" -v   # tests
.venv/bin/ruff check . && .venv/bin/ruff format --check .      # lint + format
.venv/bin/mypy --strict --exclude tests .                      # types
```

Built to the house coding standard (coding-agent repo, version v1.4.5). The spec is `SPEC.md`; the security context is `.security-audit/context.md`.
