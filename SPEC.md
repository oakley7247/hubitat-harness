# SPEC — hubitat-claude

## Goal

Let Sean control and query his Hubitat Elevation hub from Claude, and let the hub call Claude for AI-generated text inside its own automations.

## What it does

- **Exposes the hub to Claude** through an (MCP) Model Context Protocol server that runs on Sean's Mac and talks to the hub's local Maker API.
- **Reads state**: lists devices, returns any device's capabilities, attributes, and current values, returns recent device events, and lists hub modes.
- **Sends commands**: on, off, setLevel, and anything else the device itself reports as supported.
- **Answers questions on the hub** through a "Claude Assistant" virtual device driver, whose `askClaude` command posts a prompt to the Claude API and publishes the reply as a device attribute that Rule Machine can trigger on.

## What it deliberately does not do

- **No remote access.** The MCP server refuses any hub address that is not on a private network, and never uses Hubitat's cloud relay.
- **No autonomous control from the hub side.** The Groovy driver only generates text. It cannot issue device commands.
- **No commands to devices reporting a Lock, DoorControl, GarageDoorControl, Valve, SecurityKeypad, or Alarm capability**, no commands named for opening, closing, locking, unlocking, or arming whatever the device reports, and no hub mode changes — unless Sean sets `HUBITAT_ALLOW_SECURITY_COMMANDS=true`. The guard keys on what the hub reports and on what the command is named; a device that guards a boundary while reporting neither is not covered, which is what `HUBITAT_WRITABLE_DEVICE_IDS` exists for.
- **No scheduling of its own.** Rule Machine already schedules; this adds nothing on top.
- **No voice interface, and no always-on listening.**

## Security surface

- **Untrusted inputs:** device labels and attribute values from the hub (set by whoever installed each device, and read into Claude's context), tool arguments chosen by the model, and the Claude API's own responses.
- **Sensitive data touched:** the Maker API access token, which is full control of the home's devices, and an Anthropic API key stored on the hub.
- **Worst plausible failure:** a prompt injection hidden in a device label persuades Claude to unlock a door; or a leaked Maker API token gives a stranger on the network the same control. Second worst: a misfiring hub rule calls the Claude API in a loop and runs up a bill.

## Done means

- [ ] The MCP server lists Sean's real devices and toggles one from Claude Code.
- [ ] The Groovy driver returns a Claude reply into its `lastReply` attribute on the hub.
- [ ] Guarded devices and hub modes are refused unless explicitly enabled, and that refusal is proven by a test.
- [ ] The Maker API token never appears in a log, an error message, or a redirect.
- [ ] Tests green, lint clean, types clean, security preflight passed, and an independent audit verdict of PASS.

## Needs from Sean

- **Enable Maker API on the hub** and supply the app id, access token, and hub IP. Setup steps are in the README. Without these the server starts and exits with a message naming the missing variable.
- **An Anthropic API key** for the Groovy driver. Without it, `askClaude` reports the missing key and does nothing.

## Open questions

- None outstanding. Direction, hub access, repo name, and visibility were settled before the build.

---
**Approved by Sean:** 2026-08-02 · **Standards version:** v1.4.5
