# Security audit ledger — hubitat-claude

What each independent audit found, and what was done about it. The auditor reads this to tell a new finding from a returning one; without it, every round starts from zero.

Format: one section per audit, newest first. Every finding is listed with its outcome, including the ones fixed within the hour.

---

## Audit 4 — `514759b` · 2026-08-03 · verdict PASS

Focused re-audit of the `ea364b7..514759b` delta.

| ID | Severity | Finding | Outcome |
|---|---|---|---|
| A4-LOW-1 | Low | Both concurrency barriers wrote after the preamble, so two simultaneous asks could read a stale marker and both dispatch | **Fixed** in `bc5bef0`. The in-flight marker is now claimed on entry and released if the call turns out not to dispatch. |

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

**Every remediation round in this project introduced a defect of its own.** Round 1 created two Mediums, round 2 created one Low, round 3 created one Low. In each case the new defect was in code that did not exist before the fix, and in each case a scanner found none of them. Treat the changed code as the highest-yield place to look, not the lowest.

**The Groovy driver has no automated coverage.** No test harness exists for it, and no static analyser available here ships Groovy rules — semgrep walks the file without analysing it. Four of the findings above live in that file. Its review is entirely manual, every time.

**Two facts about the deployment cannot be settled from this repository**, and both are named at the findings they affect: whether Hubitat serialises command invocations per device, and whether the hub exposes any door, gate, or garage opener as a plain switch. The second is what `HUBITAT_WRITABLE_DEVICE_IDS` exists for.

---
**Last updated:** 2026-08-03 · after audit 4
