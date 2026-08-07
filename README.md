# hubitat-harness

Connects a Hubitat Elevation hub to Claude, in both directions. An (MCP) Model Context Protocol server lets you ask Claude to check sensors and control devices; a Groovy driver lets hub automations ask Claude a question and act on the answer.

Everything stays on your local network. The server refuses any hub address that is not private, and never uses Hubitat's cloud relay. The optional automations app is the one qualifier: Hubitat publishes a cloud URL for it whether or not you use one, and the app refuses requests arriving that way — see that section below.

## Install

```bash
git clone https://github.com/oakley7247/hubitat-harness.git
cd hubitat-harness
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
claude mcp add hubitat --env-file .env -- /full/path/to/hubitat-harness/.venv/bin/hubitat-harness
```

To check the wiring before registering it, run it directly — it exits immediately with the name of the first missing or invalid setting, and otherwise waits for MCP traffic on stdin:

```bash
set -a && source .env && set +a && .venv/bin/hubitat-harness
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

## The Claude Automations app

`apps/claude-automations.groovy` and `apps/claude-automation-rule.groovy` let Claude write automation rules onto the hub. Rules run on the hub itself, unattended, whether or not this server is running.

**Partly proven on hardware.** Installed and verified on a real hub on 2026-08-05: the endpoints answer, the device pool reads back with attributes and commands, and the local-only check turns away a cloud request. The rule engine itself — triggers firing, conditions evaluating, actions running — has not yet been exercised on hardware. Expect to find problems there.

To install it:

1. On the hub, open **Developer Tools → Apps Code → New App**, paste `claude-automations.groovy`, and **Save**. Then **OAuth → Enable OAuth in App**.
2. Repeat for `claude-automation-rule.groovy`. It needs no OAuth — it is only ever a child.
3. Open **Apps → Add User App**, choose **Claude Automations**, and pick the devices Claude may use.
4. Copy the app id and token from that page into `.env` as `HUBITAT_AUTOMATIONS_APP_ID` and `HUBITAT_AUTOMATIONS_TOKEN`, then restart the server.

Then ask Claude for an automation in plain language. It calls `list_rule_devices` to see what the pool holds, writes a rule spec, and `create_rule` submits it. The hub checks every device id, attribute, command, and mode name against what it actually reports, and refuses the whole rule with reasons if anything is wrong.

Each rule appears on the hub under **Apps**, indented beneath Claude Automations, with its own page: the rule in plain English, an enable toggle, a fire count, a **Run now** button, and the raw spec in an editable box. Deleting a rule is deleting an app.

### What bounds it

**The device pool is the fence, and the hub enforces it.** A Hubitat app can only command devices selected in its preferences. Claude cannot add to that list, and no endpoint exposes a way to.

**Boundary devices are off by default.** Locks, doors, garage doors, valves, keypads, alarms, and hub mode changes are refused — checked when a rule is created and again every time it fires, because a device can leave the pool or be swapped for another driver long after a rule was written. The override is a toggle on the app's page, deliberately not an environment variable: a rule that unlocks a door unattended should cost physical access to the hub.

**A firing-rate trip stops runaway rules.** More than 30 firings in 10 seconds means rules are triggering each other, so every rule stops until you clear it by hand on the app's page.

**Claude never writes Groovy.** It submits JSON, which the app reads with a switch statement. Nothing from the model is evaluated as code.

### The cloud URL, and why one setting is load-bearing

Hubitat publishes a **cloud URL** for any OAuth app, reachable from the internet by anyone holding the token — whether or not you use it. The app refuses requests whose `Host` header is not the hub's own address.

**That refusal was verified against a real hub on 2026-08-05:** a call over `cloud.hubitat.com` came back with the app's own 409, so Hubitat's relay presents a `Host` the check rejects.

Read that precisely. The cloud path still reaches the app — the check is the only thing that turns it away. So **Refuse requests that did not arrive over the local network** is a security control, not a preference; leave it on. Re-run the test after a hub firmware update, since the relay's behaviour is Hubitat's to change. The app's page has a **Rotate token** button if the token ever travels somewhere it shouldn't.

## Development

```bash
.venv/bin/python -m unittest discover -s . -p "test_*.py" -v   # tests
.venv/bin/ruff check . && .venv/bin/ruff format --check .      # lint + format
.venv/bin/mypy --strict --exclude tests .                      # types
```

Built to the house coding standard (coding-agent repo, version v1.4.5). The spec is `SPEC.md`; the security context is `.security-audit/context.md`.
