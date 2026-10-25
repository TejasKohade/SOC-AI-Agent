# Investigation: AutoSOC runtime

**Date:** 2026-10-17
**Scope:** The repository as it exists now: scenario replay, live HTTP ingest, and the continuous stream. This replaces the morning report, which only covered replay and VM. No single error was supplied.

## Summary

AutoSOC is still one Python process and one SQLite file. Three feeds now enter it. Scenario replay builds every event up front and then runs the case machine. Live ingest accepts HTTP or syslog, keeps one rule engine across requests, and waits for a quiet period before the agents run. The stream loop emits benign traffic, injects attacks, and adds behavior baselines on top of the same rules. All three still meet at `orchestrator.process_alert`, then triage, investigation, response, the approval gate, and mock tools. The new feeds do not get a new gate. They reuse helpers that a caller can skip: `tier_override`, `case_id=None`, a borrowed `ToolBox("triage")`, and a rule match error that is discarded. The suite grew to 33 tests. Ingest tests call `flush()` so the settle wait never runs, and a SOC scenario still passes when a tier-2 action is only planned.

## Root Cause

There is no single defect. The structural source is that detection, settling, budgets, and the approval gate are functions a feed can route around, while the tests score the offline stand-in and the YAML oracle.

- Replay, ingest, and stream each construct their own `RuleEngine`. `RuleEngine.process` still catches every match exception and continues, with no audit row (`autosoc/siem.py`).
- Stream detection is `rules.process` plus `baselines.ask` (`autosoc/stream/engine.py`). A baseline alert is stored and handed to `process_alert` with a synthetic `rule_id` such as `baseline-rare-process`. It never passed through a Sigma rule. Warm-up stores events and teaches the baseline without detection.
- Ingest and stream each keep an in-memory settle queue and a quiet-window clock. `db.wipe()` clears tables and does not reset that memory. Tests call `ingest.flush()`, which drains the queue immediately.
- The gate is still `compute_tier`, except `soar.submit` prefers `tier_override`. VM remediation always sets that override. `auto_if_high_confidence` executes some tier-2 steps with no approver. Reporting still validates `close`, and `_finish` still ignores it.
- LLM and tool budgets still no-op when `case_id` is missing. The VM agent and the weekly report pass none. Hunt cases are exempt. The counter increments before the cache lookup.

## Affected Components

- `autosoc/pipeline.py`: scenario replay and the VM step interpreter. `evaluate_soc` is still the test oracle.
- `autosoc/telemetry.py`: scenario YAML to events. Ingest reuses `normalise` only.
- `autosoc/ingest.py`: `POST /ingest` and `POST /ingest/syslog`, a process-wide rule engine, and a settle worker. `run_id` is the constant `"live"`.
- `autosoc/mocks/app.py`: mounts the ingest router beside the mock tool API.
- `tools/send_logs.py`: ships a scenario, a jsonl file, or syslog at the ingest URLs. No test imports it.
- `autosoc/stream/engine.py`: continuous loop, settle, scoreboard, and incident correlation after a non-benign verdict.
- `autosoc/stream/simulator.py`: synthetic attacks, including an exfil flow large enough to match `autosoc-data-exfiltration`.
- `autosoc/detect/baseline.py`: stream-only alerts that skip the rule files.
- `autosoc/incidents.py`: groups stream cases. It does not change the approval gate.
- `autosoc/siem.py`: shared rule engine and event store. Every stored event is categorised.
- `autosoc/agents/orchestrator.py`: the only case machine. Enrichment builds a `ToolBox` as `"triage"` for search. `verify` reads mocks with raw HTTP.
- `autosoc/agents/base.py`: LLM budget, one retry, untrusted wrapping. Offline skips the second try.
- `autosoc/soar.py`: playbook expand, tier, submit, execute. Lazy callbacks into the orchestrator and VM lifecycle.
- `autosoc/vm/lifecycle.py`: remediation tiers stamped in Python. Tickets go through `tickets_api()`, not the playbook runner.
- `autosoc/llm.py`: Bedrock, then OpenRouter, then the offline callable. This matches the current README.
- `autosoc/db.py`: one file for events, alerts, cases, actions, findings, incidents, and injections.
- `ui/app.py`: replay, live logs, stream scoreboard, approvals, and direct SQL.
- `tests/test_scenarios.py`, `test_ingest.py`, `test_stream.py`, `test_guardrails.py`: 33 tests, all offline.
- `siem/rules/`: 12 rules. `scenarios/soc/`: 8 scenarios. Exfil, account creation, remote exec, LOLBin, and LSASS access have rules and no scenario file.

## Data Flow

Replay: `pipeline.run_soc` loads YAML, `telemetry.generate` expands it, `_replay` stores each event and runs a fresh `RuleEngine`, then calls `process_alert` one alert at a time. Optional `--approve` approves every pending action as both analyst and SOC lead.

Live: `POST /ingest` flattens the body through `telemetry.normalise`, stores it, and runs the long-lived engine. Alerts sit until the host, user, or source IP has been quiet for 10 seconds, or 120 seconds have passed. `flush()` skips that wait. The HTTP handler returns before the agents finish. Syslog lines are parsed into the same function.

Stream: each tick stores an event with `run_id` `"stream"`, runs rules and baselines, and queues alerts with a shorter settle (6 seconds, max 45). After `process_alert`, a case that is not false-positive or benign is passed to `incidents.correlate`. The scoreboard marks an injection detected from the verdict alone, not from an executed action.

Shared tail: `run_case` enriches, triages, and stops on a benign verdict. Otherwise it investigates, picks a playbook, and `soar.submit` writes `actions`. Tier 0–1 executes immediately. A tier-2 step with `auto_if_high_confidence`, a malicious verdict, confidence at least 0.95, and no raise reasons also executes. Everything else waits. `execute` posts through `ResponseClient` to the in-process mock app unless `MOCK_BASE_URL` is set. When nothing is pending, `_finish` verifies mock state and writes the report.

VM jobs stay a fourth entry: `pipeline.run_vm` and the scheduler call `lifecycle`, which submits patches with `tier_override` and the same `ResponseClient`.

## Test Gap Analysis

`tests/conftest.py` forces `LLM_PROVIDER=offline` and wipes the database before every test. It does not reset the ingest engine or the stream baselines, which live in process memory.

What the 33 tests lock in:

- Eight SOC scenarios and nine VM scenarios through `pipeline.run()["passed"]`.
- Three approval-loop runs that require `closed` and `all_verified`, and only with `auto_approve=True`.
- Three ingest tests. They POST the bruteforce scenario or syslog, then `flush()`. Tool names are taken from `case_actions` with no check that the action is `executed`.
- Four stream tests. Detection rate must be at least 0.75. A non-benign verdict counts as detected.
- Six guardrail checks that call `wrap`, `ToolBox`, `compute_tier`, or `scoring.risk` directly.

`evaluate_soc` still treats any action row, including `pending_approval`, as proof the expected tool was chosen. `no_wrong_auto_actions` looks only at executed tools. A bruteforce case can pass while session revoke is still waiting and `verify` has not run.

The ingest settle window, the background worker without `flush()`, a match exception, `tier_override`, `case_id=None`, cache-versus-budget, `tools/send_logs.py`, the scheduler, and the UI have no test. Only `ssh-bruteforce-01` is shown to match between ingest and replay. The other four rules with no scenario never appear in `test_soc_scenario`.

The offline triage stand-in keys its verdict on rule id and mock intel. A change to that stand-in satisfies the YAML `expect` block without constraining Bedrock or OpenRouter.

## Similar Patterns

The sound split is unchanged on the SOC response path: the agent returns a plan, `soar.submit` freezes the tier on the row, and only `ResponseClient` posts to EDR, firewall, IdP, email, and patch. Tickets and `verify` already sit beside that split. Stream baselines now sit beside the rule engine the same way: a second producer of alerts, joined only at `process_alert`.

| Concern | Path that enforces it | Path that does not |
|---|---|---|
| Detection | `RuleEngine.process` on replay, ingest, and stream | Match errors discarded. Baselines emit alerts with no rule file. Warm-up stores events and does not detect. |
| When agents run | Replay sees the whole window first | Ingest and stream wait on an in-memory clock. `flush()` and a wiped database do not share that clock. |
| Actuation | `soar.execute` → `ResponseClient` | `tickets_api()` posts tickets. Mock POST routes accept any client that can reach them. |
| Tiers | Playbook YAML plus `compute_tier` | `tier_override` on VM patches. `auto_if_high_confidence` runs some tier-2 steps. A suspicious verdict forces tier 2 in the orchestrator. |
| Budgets | `_use_budget` and `ToolBox.call` when `case_id` is set and the case is not a hunt | VM agent, weekly report, and a missing case id |
| Closure | `_finish` from action status and `verify` | Reporting `close` is validated and ignored |
| What "detected" means | Scenario `expect.detected` | Stream scoreboard uses the verdict only |

Industry practice keeps Sigma conditions as a boolean detection language, not host `eval`, and keeps SOAR off raw telemetry: a case is the unit that reaches the gate, and irreversible actions wait ([Sigma conditions](https://sigmahq.io/docs/basics/conditions.html), [SOAR playbook automation](https://www.logparsing.com/soar-playbook-automation/)). AutoSOC's three feeds do meet at the case. The baseline detector and the settle queues are extra producers and clocks that the gate cannot see.

## External Research

- Sigma conditions are AND, OR, NOT, and `1 of` / `all of` over named selections. They are meant to be interpreted. AutoSOC tokenises a subset and finishes with `eval` on that token string. An illegal token becomes a swallowed exception, so the event produces no alert and no fault. Source: [Sigma specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md), [Sigma conditions](https://sigmahq.io/docs/basics/conditions.html).
- A SOAR engine should consume a case, not the raw event, and should auto-run only a high-confidence, reversible action. Destructive actions wait, and a timed-out approval defaults to deny. AutoSOC auto-runs tier 0–1 and some tier-2 malware steps. Stale approvals are escalated in `soar.escalate_stale` and are not executed. Source: [SOAR playbook automation](https://www.logparsing.com/soar-playbook-automation/).
- HITL guidance puts irreversible or high-blast-radius actions behind an explicit approval, and leaves routine reversible work automatic. That matches the intended tier split. It does not match a second detector that can open a case with a `rule_id` no playbook lists, which then falls through the offline response mapper. Source: [HITL controls](https://checkmarx.com/learn/ai-security/human-in-the-loop-cybersecurity-designing-hitl-controls-for-ai-and-appsec/).

## Recommendations

These are architectural directions, not patches.

1. **One alert type, one detector result.** Replay, ingest, stream rules, and baselines should emit the same alert record, including which detector fired and whether the detector faulted. `RuleEngine.process` returns faults instead of swallowing them. A baseline `rule_id` is either registered like a Sigma rule, with a playbook, or it cannot open a response. Warm-up stays a learning mode and cannot be confused with a detection pass.

2. **One clock for "the window is complete."** Replay, ingest settle, and stream settle should be the same wait policy, driven by event time in the database, not a private dict that `db.wipe()` leaves behind. `flush()` becomes "advance that clock," so a test cannot pass by skipping the wait the live feed uses.

3. **One grant for actuation, tier, and budget.** The same policy object from the earlier rectify plan: `compute_tier` is the only mint of a tier, a budget scope is required for every model and tool call, and `ResponseClient` is the only POST. VM patches, tickets, and baseline-driven cases use it. `close` leaves the reporting schema so case status has one writer.

4. **Tests that read rows, per feed.** For each shipped rule id, one scenario or one stream injection must fire it, including `autosoc-data-exfiltration`. Assert action status, not the tool name on a planned row. Assert that ingest without `flush()` waits out the quiet window, and that a broken rule writes a fault on all three feeds. Keep the offline stand-in for determinism, and stop using it as the definition of a correct verdict.
