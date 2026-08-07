# rules/

Local copies of the automation rules running on the hub. **The `.json` files here are gitignored** — this README is the only tracked file in the folder.

## Why they are not committed

A rule is hub state, not code. The hub is the authority on what is running; a committed copy would be a second source of truth that drifts the moment anyone edits a rule on the hub's own page. These files are a backup you can restore from, not a definition the hub follows.

They also describe the layout of a home — which sensor guards which door, which light it drives — and that is worth keeping off a remote, private repository or not.

## What is in them

Each file holds one rule's spec exactly as `create_rule` accepts it. Nothing else: no rule id, no fire count, no timestamps. That is deliberate — the hub's validator refuses keys the schema does not define, so a file with extra metadata could not be resubmitted. The rule id lives in the filename instead.

## Naming

Rules are named **Room - Trigger Device - Action Device**:

```
Bathroom - Motion Sensor - Countertop Light
Hallway - Front Door Sensor - Front Ceiling - Open
```

Device names are shortened to the part that identifies them, dropping the room prefix the label already carries — `Bathroom - Countertop Light` becomes `Countertop Light`, since the room is the first segment.

**A fourth segment is added only to break a tie.** Two rules on the same trigger and action device, differing only by trigger value, would otherwise get identical names and be indistinguishable in the hub's Apps list. The pair on the front door is the case: one fires on `open`, one on `closed`, so each carries its trigger value at the end.

Names may not contain `<`, `>`, `&`, `"`, `'`, or a backtick, and cap at 80 characters. The filename slug is derived from the name automatically, so renaming a rule renames its file and removes the old one.

## Restoring one

Ask Claude to create a rule from the file's contents, or post it directly:

```bash
curl -X POST -H 'Content-Type: application/json' \
  --data @rules/304-hallway-ceiling-on-when-front-door-opens.json \
  "http://<hub-ip>/apps/api/<app-id>/rules?access_token=<token>"
```

The hub assigns a new rule id on restore, so rename the file afterward to match.

## Keeping them current

Set `HUBITAT_RULES_DIR` in `.env` to this folder's absolute path and the server maintains them itself: every rule created, updated, enabled, disabled, or deleted through Claude rewrites or removes its file immediately. Leave the variable unset and the server never writes to disk.

That covers changes this server makes. It cannot see a rule you edit on its own page on the hub, or disable with the toggle there — those never reach the Mac. Ask Claude to **sync rules** after any hub-side change, or periodically; that pulls every rule, rewrites all the files, and deletes copies of rules the hub no longer has.

A write that fails never fails the rule change itself. The hub is the authority; if a copy cannot be written, the tool still reports the rule change as the success it was and says the copy is stale.
