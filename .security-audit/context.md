# Security context — hubitat-claude

## What this is

Two pieces that connect a Hubitat Elevation home-automation hub to Claude. The first is a Python (MCP) Model Context Protocol server that runs on Sean's Mac as a subprocess of an MCP client (Claude Code or Claude Desktop), speaks MCP over stdio, and calls the hub's local Maker API over HTTP. The second is a Groovy driver installed on the hub itself, which posts a prompt to the Anthropic Messages API over HTTPS and stores the reply in a device attribute.

## Exposure

**The MCP server listens on nothing.** It has no network listener of any kind — it reads MCP requests on stdin and writes responses on stdout, as a child process of the client that launched it. Its only outbound traffic is HTTP to one private IP on the local network, port 80 by default. That claim depends on `maker_api.py` passing an empty `ProxyHandler` to `build_opener`: urllib's default seeds a proxy from `http_proxy`/`HTTP_PROXY`/`ALL_PROXY` in the inherited environment, which would otherwise send the token-bearing URL to an arbitrary host.

**The Groovy driver has no inbound surface either.** It runs inside the hub's app sandbox and is invoked by Rule Machine, a dashboard, or the device page. Its only outbound traffic is HTTPS to `api.anthropic.com`.

Neither component is internet-facing. Nothing accepts a connection.

## Who can reach it

**Only Sean, and only through Claude.** The MCP server's caller is the MCP client on Sean's own machine, running as his user. There is no multi-user surface and no remote caller.

**The model is a semi-trusted caller.** Claude chooses which tools to invoke and with what arguments, and can be influenced by the untrusted text described below. Tool arguments are therefore validated server-side and never treated as pre-checked.

**The hub is reachable by anyone on the local network.** That is a property of the hub, not of this code: the Maker API authenticates by a query-string token over plain HTTP, so any device on the LAN that has the token has full control of the home. This code cannot improve that; it can only avoid making it worse (see the redirect and public-address refusals below).

## Data it holds or touches

- **Maker API access token** — full control of every device the Maker API instance exposes. Read from the `HUBITAT_MAKER_TOKEN` environment variable, held in memory only, never written to disk, never logged, and deliberately excluded from every error message this code raises.
- **Anthropic API key** — held in the Groovy driver's `password`-type preference, stored on the hub. Hubitat masks it in the UI but does not encrypt it; anyone with hub admin access can read it. Never logged and never written to an attribute.
- **Device state and labels** — names, rooms, and sensor readings for the home. Not persisted by this code; passed through to the model in the tool response.
- **Prompts and replies** — the driver writes the last question and last answer to device attributes, which are visible to anyone with hub access and are retained by the hub.

No database, no cache, no log files of its own.

## Tenancy

**Single user, single hub.** One configured hub per server process; there is no tenant concept and no shared state between callers.

## Authentication and authorization

**The MCP server does not authenticate its caller** and has no way to: it is a stdio subprocess, so its caller is whoever started it, which the operating system already decides. This is the standard MCP local-server model.

**Authorization is enforced in two places in `src/hubitat_claude/server.py`:**

1. `send_command` fetches the device from the hub and refuses any command not in that device's own reported command list. The allowlist comes from the hub on each call, not from a list carried in this code and not from the model.
2. Devices carrying `Lock`, `DoorControl`, `GarageDoorControl`, `Valve`, `SecurityKeypad`, or `Alarm` are refused unless `HUBITAT_ALLOW_SECURITY_COMMANDS` is explicitly true, and so are all hub mode changes. Default is false. The check fails closed on what parsing produced, not on the raw shape: a capability list that is missing, not a list, empty, or made only of entries that yield no capability name is refused rather than read as "this device guards nothing".
3. Commands named for opening, closing, locking, unlocking, or arming (`GUARDED_COMMANDS`) are refused on any device whatever it reports, because a garage door, gate, or door strike is commonly wired as a plain relay reporting only `Switch`.
4. When `HUBITAT_WRITABLE_DEVICE_IDS` is set, `send_command` refuses every device not named in it, and `set_mode` is refused outright — a mode has no device id, so it cannot be listed, and leaving it reachable would put one write path outside the fence the setting draws. Unset by default, which means every device that passes the checks above and no restriction on modes.

**Residual risk, stated plainly:** a device that guards a physical boundary, reports no guarded capability, and is commanded by an ordinary name such as `on` is not covered by checks 2 or 3. Check 4 is the answer, and it is opt-in. Anyone deploying this should set it if such a device exists on the hub.

**Authentication to the hub** is the Maker API token, in the query string, because the Maker API offers no header-auth option. `src/hubitat_claude/maker_api.py` refuses all redirects so that credential cannot be forwarded off-host.

## Controls in front of the code

**Nothing sits in front of either component.** No reverse proxy, no WAF, no VPN, no gateway. The MCP server is a local subprocess; the driver runs inside the hub.

The only ambient controls are the operating system's process and file permissions on Sean's Mac, the local network's own boundary, and the MCP client's tool-approval prompt — which is the human gate on write operations, and is provided by the client, not by this code.

**The hub speaks plain HTTP.** Traffic between this server and the hub, including the access token, is readable by anything with packet capture on the local network. Hubitat provides no supported way to require HTTPS locally.

**The hub echoes a rejected token back in its 401 body** — observed against a real hub on 2026-08-03: `<oauth><error_description>THE-SUBMITTED-TOKEN</error_description><error>invalid_token</error></oauth>`. An error response from this hub is therefore itself a credential. `maker_api.py` raises a fixed message on 401 and never places a response body in an exception or a log, which is what keeps that out of this process's output; anything added later that logs raw hub responses would leak the token on every failed call.

## Deployment identity and secrets

**The MCP server runs as Sean's own macOS user account**, with that account's full privileges — it is not sandboxed or dropped to a lower privilege. Secrets come from environment variables, documented in `.env.example`; `.env` is gitignored.

**The Groovy driver runs inside the hub's Groovy sandbox**, which forbids defining classes, threads, filesystem access, and reflection. Its secret comes from a driver preference stored on the hub.

---
**Last verified accurate:** 2026-08-03 · verified against the code by the coding agent at first commit
