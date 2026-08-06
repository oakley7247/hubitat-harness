# rules/

Local copies of the automation rules running on the hub. **The `.json` files here are gitignored** — this README is the only tracked file in the folder.

## Why they are not committed

A rule is hub state, not code. The hub is the authority on what is running; a committed copy would be a second source of truth that drifts the moment anyone edits a rule on the hub's own page. These files are a backup you can restore from, not a definition the hub follows.

They also describe the layout of a home — which sensor guards which door, which light it drives — and that is worth keeping off a remote, private repository or not.

## What is in them

Each file holds one rule's spec exactly as `create_rule` accepts it. Nothing else: no rule id, no fire count, no timestamps. That is deliberate — the hub's validator refuses keys the schema does not define, so a file with extra metadata could not be resubmitted. The rule id lives in the filename instead.

## Restoring one

Ask Claude to create a rule from the file's contents, or post it directly:

```bash
curl -X POST -H 'Content-Type: application/json' \
  --data @rules/304-hallway-ceiling-on-when-front-door-opens.json \
  "http://<hub-ip>/apps/api/<app-id>/rules?access_token=<token>"
```

The hub assigns a new rule id on restore, so rename the file afterward to match.

## Keeping them current

They are a snapshot, taken by hand. Nothing syncs them. After changing a rule — through Claude, or on the rule's own page — ask Claude to refresh the copy, or the file becomes a record of something that no longer exists.
