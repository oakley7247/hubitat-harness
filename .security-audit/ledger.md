# Security audit ledger — hubitat-claude

What each independent audit found, and what was done about it. The auditor reads this to tell a new finding from a returning one; without it, every round starts from zero.

Format: one section per audit, newest first. Every finding is listed with its outcome, including the ones fixed within the hour.

---

## Audit 6 — `d79c9fb` · 2026-08-05 · verdict CONDITIONAL

Deploy-scope audit of the automations branch against `main`. **No regressions.** All fourteen items the ledger records as fixed across audits 1–5 were re-checked and hold, including the `http_client.py` transport extraction, which was verified line by line as control-preserving.

| ID | Severity | Finding | Outcome |
|---|---|---|---|
| A6-CRIT-1 | Critical | The rule page's editable spec box is the one sink A5-CRIT-1's escaping fix skipped, and only `name` bans markup characters — so `notify.text`, command `args`, and attribute comparison values can carry `</textarea><script>` into a durable spec that the page then renders | **Fixed, pending re-audit.** Two changes, neither depending on platform behaviour: every string a spec persists now refuses `<` and `>` at any depth, and display is separated from editing — the stored spec renders in an escaped `<pre>` and no stored value ever populates an input. |
| A6-HIGH-1 | High | Hubitat's cloud URL exposes the rule endpoints to the internet behind a `Host` check that is a no-op if the relay rewrites the header | **Open**, carried from A5-HIGH-1. Blocks installation. Cannot be closed from the repository. |
| A6-MED-1 | Medium | Two paths change a rule's stored spec without an audit entry: `apiUpdateRule` lacks the rollback `apiCreateRule` got in A5-LOW-3, and the child's "Apply edited spec" button records nothing at all. A throwing `refreshTriggers` also leaves the new spec persisted with stale subscriptions after a 500 | **Fixed, pending re-audit.** The update path restores the prior spec and returns 400; hand edits record an `edited by hand` entry carrying the spec. |
| A6-LOW-1 | Low | `set_rule_enabled` skips the writable-device allowlist when the fetched spec is not a dictionary — "cannot determine" resolving to "permit" | **Fixed, pending re-audit.** An unreadable spec now refuses the enable, with a test. |
| A6-INF-1 | Info | `RecursionError` is uncaught in `_checked_spec`, and the depth bound added for A5-INF-4 is skipped entirely when no allowlist is set — which is the default | Fixed, pending re-audit. Caught in `_checked_spec`, with a test that nests past the recursion limit. |
| A6-INF-2 | Info | `toLowerCase()` uses the JVM default locale in the guarded-command check; under a Turkish locale `SIREN` lowercases outside the list | Fixed, pending re-audit. Both call sites use `Locale.ROOT`. |
| A6-INF-3 | Info | A5-INF-3 was fixed in one of three places; `SPEC-automations-app.md` still says "six tools" twice | Fixed, pending re-audit. Also corrected two other spec statements the build had outrun. |

**Found on first contact with real hardware, after audit 6:** every endpoint returned HTTP 200 with a zero-length body. `respond()` called `render()` and returned null, treating render as a side effect, but Hubitat sends what the mapping handler *returns*. The local-only check had the same shape, so a refused cloud request would have answered an empty 200 rather than a visible 409. Fixed in `e000560`. Neither audit could have caught it — both reviewed the Groovy by reading, and the defect exists only in how the platform treats a return value.

Confirmed intact: the fail-closed capability parse, the writable-device allowlist on all three write paths, the charge-after-conditions ordering, both concurrency barriers, the device-pool fence, the fire-time boundary re-check, and command dispatch gated on `hasCommand`.

## Audit 5 — `d79c9fb` · 2026-08-05 · verdict BLOCK

First audit of the automations component: two Hubitat apps, a shared HTTP transport extracted from `maker_api.py`, a rules client, and seven MCP tools. The extraction was verified line by line as control-preserving. The blocking finding is a class this project had not met before — output encoding.

| ID | Severity | Finding | Outcome |
|---|---|---|---|
| A5-CRIT-1 | Critical | Model-supplied rule names and device labels reached the hub's admin page through `paragraph`, which Hubitat renders as HTML — on an origin that has no login by default, so an injected label was script with rights to install Groovy and read both tokens | **Partially fixed** before commit; verified partial by audit 6. All twelve `paragraph` sinks now escape through `safe()`, and rule names refuse markup characters. The editable spec box was left unescaped on an assumption about the platform, and the character ban covers `name` only — see A6-CRIT-1. |
| A5-HIGH-1 | High | Hubitat publishes an internet-reachable cloud URL for any OAuth app; the `Host`-header check in front of it is unverifiable without a hub, and is a no-op if the relay rewrites the header | **Open**, carried to A6-HIGH-1. Cannot be closed from the repository. Named in `SPEC-automations-app.md` open question 1 as blocking installation, and stated plainly in `README.md` rather than described as closed. |
| A5-MED-1 | Medium | `_refuse_unwritable_devices` walked for `deviceId` keys, so a `setMode` action — which carries none — passed the allowlist; and `set_rule_enabled` ran no spec check at all. Reopened the class `A2-MED-1` closed, through a path that did not exist then | **Fixed** before commit. `setMode` is refused while the allowlist is in force, and enabling re-checks the rule's stored spec. Both covered by tests. |
| A5-MED-2 | Medium | The rule history stored only a timestamp, a verb, and a name — so the spec's named control against a rule written under injection did not exist | **Fixed** before commit. Each entry carries the submitted spec, capped, and the page shows the 30-day window the spec called for. |
| A5-MED-3 | Medium | The rate trip was charged before conditions were evaluated, so three ordinary rules on a chatty sensor could stop every rule on the hub with no fault present | **Fixed** before commit. The charge moved to immediately before the actions run. Inverted the same ordering `A3-LOW-1` established. |
| A5-LOW-1 | Low | `Run now` checked neither the enable toggle nor the master switch, so the kill switch was not one | **Fixed** before commit. |
| A5-LOW-2 | Low | The per-rule re-fire interval read `state` and wrote it late, repeating `A4-LOW-1`'s shape in new code | **Fixed** before commit. Moved to `atomicState` and claimed on entry. |
| A5-LOW-3 | Low | A throwing action abandoned every later action silently, and a throwing `configureRule` left a persisted child after an error response that said nothing was created | **Fixed** before commit. Per-action isolation with a recorded note; failed creation rolls the child back. |
| A5-LOW-4 | Low | The spec size cap lived only on the Mac, and unknown keys were accepted, persisted, and returned to the model as unvalidated text | **Fixed** before commit. The hub caps size itself and refuses keys the schema does not define, at every level. |
| A5-LOW-5 | Low | The local-only refusal answered 403, which the client never reads a body for — so a Host mismatch reached the operator as "bad token" | **Fixed** before commit. The refusal answers 409. |
| A5-INF-2 | Info | A comment claimed the token is shown once; the page redisplays it every view | Fixed before commit. |
| A5-INF-3 | Info | `SPEC-automations-app.md` said six tools; seven ship | Fixed before commit. |
| A5-INF-4 | Info | `collect_device_ids` recursed unbounded, ahead of the size check, so a nested spec raised `RecursionError` rather than a refusal | Fixed before commit. Depth bound, with a test. |

## Audit 4 — `514759b` · 2026-08-03 · verdict PASS

Focused re-audit of the `ea364b7..514759b` delta.

| ID | Severity | Finding | Outcome |
|---|---|---|---|
| A4-LOW-1 | Low | Both concurrency barriers wrote after the preamble, so two simultaneous asks could read a stale marker and both dispatch | **Fixed** in the commit that introduced this file. The in-flight marker is claimed on entry and released if the call turns out not to dispatch. |

Confirmed intact: the writable-device allowlist on both write paths, the fail-closed capability check, the NAT64 refusal, and the budget split.

## Audit 3 — `ea364b7` · 2026-08-03 · verdict PASS

| ID | Severity | Finding | Outcome |
|---|---|---|---|
| A3-LOW-1 | Low | The daily counter charged before the in-flight guard refused, so a question that never went out still spent a call — inverting the cap, since a stalled rule was throttled 24× faster than a working one | **Fixed** in `514759b`. Budget split into a read-only check and a charge taken immediately before dispatch. |
| A3-LOW-2 | Low | `_unwrap` missed NAT64; CPython reports `64:ff9b:1::/48` as private, so an address whose whole purpose is to forward to an arbitrary IPv4 host was admitted | **Fixed** in `514759b`. The whole `64:ff9b::/32` is refused rather than decoded. |
| A3-INF-1 | Info | Stale comment describing 24 concurrent requests, made false by the in-flight guard | Fixed in `514759b`. |
| A3-INF-2 | Info | `SPEC.md` omitted that mode changes also require the writable list to be unset | Fixed in `514759b`. |
| A3-INF-3 | Info | The trickle test's margin was 7.5× its budget and asserted only the exception type | Fixed in `514759b`. Margin tightened, assertion names the failure. |

## Audit 2 — `61f80e1` · 2026-08-03 · verdict CONDITIONAL

Both Mediums were introduced by the first remediation round.

| ID | Severity | Finding | Outcome |
|---|---|---|---|
| A2-MED-1 | Medium | `set_mode` ignored `HUBITAT_WRITABLE_DEVICE_IDS`, so an operator who narrowed Claude to one device still left mode changes reachable — and mode drives Safety Monitor | **Fixed** in `ea364b7`. Mode changes are refused outright while the allowlist is in force. |
| A2-MED-2 | Medium | `refundCall` returned the charge on any `hasError()`, which covers timeouts and HTTP errors — so a rule whose calls all failed never advanced the counter | **Fixed** in `ea364b7`. The refund is gone; charge-on-dispatch is the whole rule. |
| A2-LOW-1 | Low | The read deadline was checked only between reads, and `read(n)` blocks until it has all n bytes — so the bound existed on paper only | **Fixed** in `ea364b7`. `read1` plus a socket timeout tightened to the remaining budget. |
| A2-LOW-2 | Low | The capability check tested the raw list, so `[None]` passed the shape test and then parsed to nothing | **Fixed** in `ea364b7`. The test moved to what parsing produced. |
| A2-LOW-3 | Low | A superseded reply was discarded silently, leaving a rule waiting forever for an answer it had paid for | **Fixed** in `ea364b7`. A concurrent ask is refused instead. |
| A2-LOW-4 | Low | `_unwrap` missed Teredo, and CPython reports `2001::/32` as private | **Fixed** in `ea364b7`. |
| A2-LOW-5 | Low | `.gitleaksignore` held a raw secret where gitleaks expects a fingerprint, so the secret-scan gate failed on every run | **Fixed** in `ea364b7`. Replaced with a scoped `.gitleaks.toml` allowlist. |

## Audit 1 — `b86cbb0` · 2026-08-03 · verdict CONDITIONAL

First audit of this repository.

| ID | Severity | Finding | Outcome |
|---|---|---|---|
| A1-HIGH-1 | High | The guarded-capability check failed open on a missing or malformed `capabilities` key, so a lock could become commandable with the flag off. The two gates had opposite failure modes and the safety-critical one was permissive | **Fixed** in `61f80e1`. |
| A1-MED-1 | Medium | A comment claimed the argument filter rejected the delimiters Hubitat splits on; the comma — the one it actually splits on, after decoding — was absent, so one argument arrived as several | **Fixed** in `61f80e1`. |
| A1-MED-2 | Medium | The guard keyed on declared capability, so a garage door or gate wired as a plain relay reporting only `Switch` was unguarded | **Fixed** in `61f80e1` by a command-name rule plus an opt-in device allowlist. The residual — such a device commanded by an ordinary `on` — is documented in `context.md` rather than claimed closed. |
| A1-MED-3 | Medium | urllib seeds a proxy from `http_proxy` in the inherited environment, so one variable routed the token-bearing URL off-host | **Fixed** in `61f80e1`. |
| A1-MED-4 | Medium | The daily cap charged on a successful reply, missing the two responses Anthropic bills in full but that carry no answer | **Fixed** in `61f80e1`, and again in `514759b` after the first fix over-corrected. |
| A1-MED-5 | Medium | One pinned direct dependency pinned nothing beneath it; 34 transitive distributions floated and the dependency scan had zero coverage | **Fixed** in `61f80e1`. Hash-pinned lockfile, frozen CI install, audit reads the lockfile before anything installs. |
| A1-LOW-1 | Low | The address check was deny-public rather than allow-private, admitting carrier-grade NAT and IPv6-wrapped public IPv4 | **Fixed** in `61f80e1`. |
| A1-LOW-2 | Low | The 2 MiB cap bounded bytes and nothing else — no time bound, no cap on what reached the model's context | **Fixed** in `61f80e1`. |
| A1-LOW-3 | Low | Driver budget counters were non-atomic | **Fixed** in `61f80e1`. Moved to `atomicState`. |
| A1-LOW-4 | Low | A reply could not be correlated with the question that produced it | **Fixed** in `61f80e1`. |

---

## Standing notes

**Every remediation round in this project introduced a defect of its own.** Round 1 created two Mediums, round 2 created one Low, round 3 created one Low, and the automations build created three of its own findings. In each case the new defect was in code that did not exist before the fix, and in each case a scanner found none of them. Treat the changed code as the highest-yield place to look, not the lowest.

**Untrusted text reaching a Hubitat page is an HTML sink.** `paragraph` renders markup by design, and Hub Login Security is off by default, so the admin origin runs unauthenticated. Anything model-supplied or device-supplied must be escaped at the point of rendering, never at the point of storage — `A5-CRIT-1` was the project's first output-encoding defect and it was the worst finding in five audits. Every new page sink is a repeat until proven otherwise.

**A control's promise has to be re-checked against every path, not the path it was written for.** `A2-MED-1` and `A5-MED-1` are the same defect eighteen months apart in project time: a device allowlist that covered the write path in front of it and missed the one added later. When a new write path ships, enumerate the existing guards and ask which of them it walks past.

**The Groovy driver has no automated coverage.** No test harness exists for it, and no static analyser available here ships Groovy rules — semgrep walks the file without analysing it. Four of the findings above live in that file. Its review is entirely manual, every time.

**Two facts about the deployment cannot be settled from this repository**, and both are named at the findings they affect: whether Hubitat serialises command invocations per device, and whether the hub exposes any door, gate, or garage opener as a plain switch. The second is what `HUBITAT_WRITABLE_DEVICE_IDS` exists for.

---
**Last updated:** 2026-08-05 · after audit 6
