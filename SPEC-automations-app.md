# SPEC — Claude Automations app

Second component spec, additive to `SPEC.md`. That document covers the (MCP) Model
Context Protocol server and the Claude Assistant driver, both shipped. This one covers
a new, separate thing: a Hubitat app that lets Claude write automation rules onto the
hub. It gets its own spec because it needs its own approval, its own security surface,
and its own definition of done.

## Goal

Let Sean ask Claude for an automation in plain language and have a working rule appear
on the hub — visible, editable, and removable in the hub's own UI, and running whether
or not Claude or the Mac is ever available again.

## What it does

- **Installs as a parent app plus one child app per rule.** The parent holds the device
  pool and the endpoints; each child holds one rule, its own subscriptions, its own
  schedule, and its own log stream.
- **Accepts rules as JSON**, never as Groovy. Claude writes a constrained rule spec; the
  parent validates every field against what the hub itself reports; the child's engine
  executes it. Nothing the model writes is ever evaluated as code.
- **Executes triggers, conditions, and actions** using the hub's own app APIs —
  `subscribe()` for device and location events, `schedule()` for cron and sun times,
  `runIn()` for delays, and direct device commands.
- **Exposes seven MCP tools** on the existing server: `list_rules`, `get_rule`,
  `list_rule_devices`, `create_rule`, `update_rule`, `set_rule_enabled`, `delete_rule`.
- **Shows every rule in the hub UI** with its trigger and actions in plain English, an
  enable toggle, a last-fired timestamp, a fire count, a Run Now button, the stored spec
  displayed, and a separate box for pasting a replacement.

## What it deliberately does not do

- **No Rule Machine integration.** Rule Machine's rule structures are private state with
  no supported API. This app owns its own rules rather than writing into someone else's.
  Existing Rule Machine rules are untouched and unread.
- **No Groovy from the model, ever.** The app calls no `evaluate()`, loads no code, and
  accepts no expression language. The rule schema below is the entire vocabulary.
- **No reach beyond the device pool.** A Hubitat app can only command devices selected in
  its preferences. Sean picks that set in the hub UI; Claude cannot add to it, and no
  endpoint exposes a way to.
- **No commands to boundary devices by default.** The same guarded-capability and
  guarded-command rules the MCP server enforces (`SPEC.md`, "What it deliberately does
  not do") apply here, checked twice — when a rule is created and again when it fires.
  Turning them off requires a preference set by hand in the hub UI. It is deliberately
  not an environment variable and not reachable from any endpoint, because the Mac's
  `.env` is a weaker gate than physical access to the hub.
- **No cloud dependency at runtime.** Rules run on the hub. The Anthropic API is reached
  only by an explicit `askClaude` action, and only if that action ships (see Open
  questions).
- **No self-modification.** A rule's actions cannot create, edit, enable, or delete a
  rule. Rule authorship is a human-approved path only.

## Components

| Piece | Where it runs | What it holds |
|---|---|---|
| `apps/claude-automations.groovy` | Hub | Device pool, endpoints, validation, child lifecycle, kill switch |
| `apps/claude-automation-rule.groovy` | Hub | One rule spec, its subscriptions, its execution engine |
| `src/hubitat_claude/automations.py` | Mac | HTTP client for the parent app's endpoints |
| Seven new tools in `server.py` | Mac | The MCP surface Claude calls |

## Rule schema

The complete vocabulary. Anything not listed is refused.

```json
{
  "name": "Kitchen counter light on motion after dark",
  "enabled": true,
  "trigger": {
    "type": "attribute",
    "deviceId": "241",
    "attribute": "motion",
    "changesTo": "active"
  },
  "conditions": [
    {"type": "mode", "in": ["Evening", "Night"]},
    {"type": "attribute", "deviceId": "357", "attribute": "switch", "equals": "off"}
  ],
  "actions": [
    {"type": "command", "deviceId": "357", "command": "setLevel", "args": [40]},
    {"type": "delay", "seconds": 300, "cancelOnRetrigger": true},
    {"type": "command", "deviceId": "357", "command": "off"}
  ]
}
```

**Triggers** — exactly one per rule.

| `type` | Fields |
|---|---|
| `attribute` | `deviceId`, `attribute`, and one of `changesTo`, `changes`, `risesAbove`, `dropsBelow` |
| `time` | `at` as `"21:30"`, or `"sunrise"` / `"sunset"` with optional `offsetMinutes` |
| `cron` | `expression`, a Quartz cron string |
| `mode` | `changesTo`, a mode name |
| `button` | `deviceId`, `buttonNumber`, `event` of `pushed` / `held` / `doubleTapped` |

**Conditions** — zero or more; all must hold at fire time, evaluated then, not at creation.

| `type` | Fields |
|---|---|
| `attribute` | `deviceId`, `attribute`, one of `equals`, `notEquals`, `greaterThan`, `lessThan` |
| `mode` | `in`, a list of mode names |
| `timeBetween` | `from`, `to` — clock times or `sunrise` / `sunset` with offsets |
| `dayOfWeek` | `in`, a list of day names |

**Actions** — one or more, executed in order.

| `type` | Fields |
|---|---|
| `command` | `deviceId`, `command`, `args` |
| `delay` | `seconds`, optional `cancelOnRetrigger` |
| `cancelPending` | none — drops this rule's outstanding delays |
| `setMode` | `mode`, a mode name. Refused unless boundary commands are enabled |
| `notify` | `deviceId` of a Notification-capable device, `text` |

### What validation checks, and where

The parent validates at creation; the child re-checks at fire time. Both read the hub,
not the request.

- `deviceId` must be in the parent's selected device pool.
- `attribute` must appear in that device's reported `attributes`.
- `command` must appear in that device's reported `commands`.
- Argument values must satisfy the attribute's `dataType`, and for `ENUM`, appear in its
  `values` list.
- Mode names must exist on the hub.
- A rule failing any check is refused whole, with the reason, and nothing is created.

Re-checking at fire time matters because a device can be removed from the pool, or
swapped for another driver, long after the rule was written.

### Runaway bounds

- **Rule count cap** on the parent, default 50.
- **Actions per rule cap**, default 20.
- **Minimum re-fire interval per rule**, default 1 second, to bound a sensor that chatters.
- **Firing-rate trip**, 30 firings in 10 seconds — one rule's action can trigger another
  rule's subscription, and without a bound a pair of rules drives each other indefinitely.
  See "Changed during the build" for why this replaced a cascade-depth count.
- **Global kill switch** on the parent page: one toggle stops every child from acting.

## Security surface

Everything in `.security-audit/context.md` still applies. This component adds four things.

**A standing, unattended write.** Every write today passes the MCP client's approval
prompt, with Sean watching. A rule is approved once and then fires forever, unattended,
at any hour. The approval prompt covers authorship, not execution — so the boundary-device
guard has to hold at fire time on its own, and the audit trail has to survive the session
that created it.

**A new inbound listener on the hub.** The parent app registers OAuth endpoints, which is
the first inbound surface in this project — both prior components accept no connections.
Its token is a second credential of the same weight as the Maker API token: it grants rule
authorship over the device pool. It gets its own environment variables
(`HUBITAT_AUTOMATIONS_APP_ID`, `HUBITAT_AUTOMATIONS_TOKEN`), never reuses the Maker API's,
and is subject to the same rules — never logged, never in an error message, never in a
redirect.

**A cloud URL that exists whether or not it is used.** Hubitat mints both a local and a
cloud endpoint for any OAuth app, and the cloud one is reachable from the internet by
anyone holding the token. The app refuses it by comparing the `Host` header against the
hub's own address, and that refusal was verified against real hardware on 2026-08-05.
The path is guarded, not absent: turning `refuseCloudRequests` off opens it.

**A durable prompt-injection target.** Device labels are attacker-controlled text that
reaches Claude's context. Today the worst outcome is one bad command that Sean sees in an
approval prompt. Here it is a rule that persists — so the parent records, per rule, the
creation timestamp and the full spec as submitted, and the parent page lists every rule
created in the last 30 days for review.

**Worst plausible failure:** a rule written under injection, or written correctly and then
made unsafe by a device swap, fires unattended at 3am against something that matters.
Second worst: the OAuth token leaks and a stranger writes rules over the device pool.

## Done means

- [ ] The parent app installs on the hub, exposes a device pool selector, and lists its children.
- [ ] Claude creates a rule end to end, and it appears in the hub UI under the parent.
- [ ] The created rule fires on a real device event and runs its actions.
- [ ] A rule naming a device outside the pool is refused, and a test proves it.
- [ ] A rule commanding a boundary device is refused at creation and at fire time, both proven by tests.
- [ ] Disabling a rule in the hub UI stops it firing; the kill switch stops all of them.
- [ ] Neither token appears in a log, an error message, or a redirect.
- [x] The cloud endpoint question below is resolved and the resolution is implemented.
- [ ] Tests green, lint clean, types clean, security preflight passed, independent audit verdict of PASS.

## Needs from Sean

- **Install both app files** on the hub under Apps Code, then add a Claude Automations
  instance and select the device pool. The pool is the fence; nothing else can widen it.
- **Enable OAuth** on the parent app and copy its app id and token into `.env`.
- **Decide the boundary-device default** for rules — the spec assumes off, matching the
  server.

## Open questions

1. ~~**Can the app refuse cloud-endpoint requests?**~~ **Settled 2026-08-05 on hardware:
   yes.** A call to `/pool` over `cloud.hubitat.com` returned the app's own 409, so the
   relay presents a `Host` the check rejects. The cloud path still reaches the app — the
   check is what stops it — so `refuseCloudRequests` is load-bearing, and this should be
   re-tested after a hub firmware update.
2. ~~**Does Claude get to delete and edit rules, or only create them?**~~ **Settled
   2026-08-05: full lifecycle.** All seven tools ship — create, read, list devices, update, enable/disable,
   delete — plus the parent's own append-only history of every change.
3. ~~**Does `askClaude` ship as an action in v1?**~~ **Settled 2026-08-05: deferred.**
   It is not in the actions table. Adding it later changes nothing already built.
4. **Are the default caps right?** 50 rules, 20 actions.

## Known issues

**No cross-rule delay cancellation.** `cancelPending` cancels only the rule's own pending delay, so one rule cannot cancel another's timer. A motion-off rule therefore cannot have its countdown restarted by the matching motion-on rule: leave a room at 8:00, return at 8:04:30, still there at 8:05:00, and the light goes off while you stand in it. The same flaw appears mirrored in a single rule whose clock runs from motion going active.

The agreed fix is a `cancelRule` action naming another rule id. It needs a schema addition, Groovy work on both apps, and a security-audit pass — one child acting on another is a new trust edge inside the app, and the parent would have to mediate it. Not yet built.

**Half the engine has never run on hardware.** Attribute triggers, subscription dispatch, device commands, and fire counting are verified. Conditions, delays and resume, time/cron/sun triggers, mode and button triggers, `notify`, the firing-rate trip, and the fire-time boundary refusal are not. Every defect found so far lived in that gap.

**`setColor` is unreachable.** It takes a `COLOR_MAP`, which neither write path can express — `send_command` sends one comma-free argument, and a rule's `args` passes scalars. Use `setHue`, `setSaturation`, and `setLevel` as separate actions.

## Changed during the build

**The cascade-depth cap became a firing-rate trip.** Attributing a firing to the rule
that caused it is not reliably possible on the hub — a device event looks identical
whether a person, a rule, or another app produced it — so a depth counter would have
been guesswork. In its place: more than 30 firings in 10 seconds stops every rule until
someone clears it on the app's page. It catches the same failure (rules driving each
other) with a test the hub can actually make.

---
**Approved by Sean:** _pending_ · **Standards version:** v1.4.5
