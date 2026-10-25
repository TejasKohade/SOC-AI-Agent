# Investigation: AutoSOC as it runs now

**Date:** 2026-10-17
**Scope:** `/Users/tejaskohade/Documents/Cybergate` — the current AutoSOC process: scenario replay, live ingest, the stream, vulnerability management, and the shared case machine. Earlier notes in this folder cover the same tree at earlier points. This report is the picture after re-reading the modules those notes cite.

## Summary

AutoSOC is one Python process with one SQLite database and three ways an event becomes a case, plus a fourth path for vulnerability jobs. All four share `orchestrator.process_alert` / `run_case` and the approval helper in `soar.submit`. The README describes one sequence: categorise, detect with Sigma and baselines, correlate into a scored incident, then respond by that severity. The code categorises on every stored event, runs baselines only inside the stream engine, scores incidents from the case verdict, and authorises actions from the playbook tier. “Passed” and “detected” are three different predicates. A scenario can pass while the containment action is still `pending_approval`. A stream injection counts as detected when the verdict is not benign. Neither check asks whether the gate held.

## Root Cause

There is no result type that a feed, a test, and the dashboard all have to fill in. Each surface stored a boolean for a different row.

- Scenario success is `evaluate_soc` in `autosoc/pipeline.py` (lines 97–130). `detected` is `bool(alerts)`. Expected actions match any action row with that tool name, including `pending_approval`. Only `status == "executed"` is counted when looking for unexpected tools.
- Stream success is `_match_ground_truth` in `autosoc/stream/engine.py` (lines 97–111). An injection is detected when the linked case verdict is not `false_positive` or `benign`. The scoreboard never reads `actions`.
- Incident “intel confirmation” is `any(verdict == "malicious")` inside `severity_score` in `autosoc/incidents.py`. The rationale string says intel-confirmed. Threat-intel hits are not an input, and the score does not choose a tier.
- The README step “Respond by severity” (`README.md` lines 66–67) describes the approval gate. `soar.submit` (`autosoc/soar.py` line 103) uses the playbook step and `compute_tier`, or `tier_override` when the caller supplies one. `severity_score` is a sort key.

Unmapped detectors are not a fault. `response._offline` (`autosoc/agents/response.py` lines 22–27) maps a rule id to a playbook and, if none matches, uses `malicious_ip`. Baseline ids and four Sigma ids take that default.

`Baselines.learn_from_db` (`autosoc/detect/baseline.py` lines 47–49) accepts `run_id` and ignores it. The query is every row in `events`. A stream engine started after a scenario run learns that run’s attacks as normal.

The approval helper is still skippable, which is why the scoreboards cannot see whether the gate held:

- `tier_override` replaces `compute_tier`. `lifecycle.plan_remediation` always sets it.
- `auto_if_high_confidence` executes some tier-2 malware steps when the verdict is malicious, confidence is at least 0.95, and nothing asked to raise the tier.
- `_use_budget` does nothing when `case_id` is missing. The VM agent and the weekly report call the LLM that way. The budget increments before the cache lookup.
- `RuleEngine.process` (`autosoc/siem.py` around lines 100–107) swallows match errors with `continue` and evaluates condition tokens with `eval`.
- `reporting.run` returns `close`. `_finish` (`autosoc/agents/orchestrator.py` lines 277–297) stores that report and then sets the case status from failed actions and `verify()`, without reading `close`.
- `soar.execute` records a failed mock call and continues. A failed rollback leaves the action marked executed.
- `verify()` is true when there are no executed actions to check.

## Affected Components

- `README.md`: the asyncio diagram (replay only), the “29 tests” line, and stream steps 1–5. Pytest collects 33 items from 20 test functions.
- `autosoc/pipeline.py`: fresh `RuleEngine` per replay, no settle, `evaluate_soc`.
- `autosoc/ingest.py`: long-lived engine, `run_id` `"live"`, settle 10s quiet / 120s max. `flush()` drains immediately.
- `autosoc/stream/engine.py`: rules plus baselines, `run_id` `"stream"`, settle 6s / 45s, incident correlation, scoreboard.
- `autosoc/detect/baseline.py`: second detector. `learn_from_db` is unscoped.
- `autosoc/siem.py`: condition `eval`, swallowed match errors, no fault record.
- `autosoc/incidents.py`: severity score and the intel-confirmed label.
- `autosoc/agents/response.py`: playbook fallback to `malicious_ip`.
- `autosoc/agents/orchestrator.py`: `ToolBox("orchestrator")` for intel and inventory, `ToolBox("triage")` for `cases.similar` and `siem.search` (lines 106 and 124). `_finish` ignores `close`.
- `autosoc/soar.py` and `autosoc/vm/lifecycle.py`: the gate and `tier_override`.
- `autosoc/agents/base.py` and `autosoc/llm.py`: budget before cache; providers are Bedrock then OpenRouter; offline is the caller’s fallback, not a provider in the tuple.
- `playbooks/*.yml`: eight playbooks. `data_exfiltration` is the only base tier 3.
- `siem/rules/*.yml`: twelve rules. Five have no `scenarios/soc/` file: account created, remote exec, LOLBin, LSASS access, data exfiltration.
- `tests/test_scenarios.py`, `tests/test_ingest.py`, `tests/test_stream.py`, `tests/test_guardrails.py`: the oracles. Ingest and stream tests drain with `flush()` or `_work(now=float("inf"))`.
- `tuning/suggestions/*.md`: written when a case closes. Nothing under `siem/` or `playbooks/` reads them.

## Data Flow

Replay builds a fresh rule engine, stores every event (which always categorises), matches Sigma only, and calls `process_alert` after the whole window. `run_id` is a new id. Success is the YAML `expect` block.

Ingest keeps one rule engine for the process. Alerts wait until the host, user, or source IP is quiet, or until `flush()`. There are no baselines and no incident grouping. `db.wipe()` clears tables and leaves the in-memory engine and the settle dicts in place.

Stream warms the baseline by storing and observing, without detecting. Live events are scored, then observed, then queued on the same settle idea with a shorter clock. A non-benign case is passed to `incidents.correlate`. Ground truth is updated from the verdict.

Vulnerability jobs do not emit alerts. `plan_remediation` builds steps that already contain `tier_override` and submits them through the same `soar.submit`.

`process_alert` dedupes by recent host or user, then `run_case` enriches, triages, maybe stops on a benign verdict, investigates, plans a response, and submits. `resume` stops while any action is `pending_approval`. `_finish` verifies executed actions and writes the report.

## Test Gap Analysis

| Check | What the suite does | What it leaves open |
|---|---|---|
| Scenario pass | 8 SOC and 9 VM tests assert `pipeline.run()["passed"]` | Expected tools may be pending. Unexpected tools count only if executed. |
| Closure | 3 scenarios re-run with `auto_approve=True` and expect `closed` | Does not read `report["final"]["close"]`. |
| Ingest | 2 tests call `ingest.flush()` then check tool names or `evaluate_soc` | Quiet window never elapses in a test. `db.wipe()` versus the live engine is untested. |
| Stream | Detection rate at least 0.75 after `_work(now=inf)` | Verdict counts as detection. Containment is unread. Baseline learning across `run_id`s is untested. |
| Gate | `compute_tier` and a hand-built `soar.submit(None, …)` | `tier_override`, `auto_if_high_confidence`, and a missing `case_id` budget are not asserted. |
| Rules | 8 scenario files | 5 Sigma rules and every baseline id have no scenario. Four of those Sigma ids have no playbook binding. |

`tests/conftest.py` forces `LLM_PROVIDER=offline`. The offline responders and the YAML expectations were written together, so a green run shows that the scripted path still matches its own script.

## Similar Patterns

The same shape appears in each feed: a local boolean stands in for “the pipeline did the right thing,” and a helper that can be skipped stands in for a gate.

- `evaluate_soc` treats a planned tool as the action the scenario asked for.
- The stream scoreboard treats a non-benign verdict as a caught attack.
- `severity_score` treats a malicious verdict as intel confirmation.
- `response._offline` treats an unknown detector as the `malicious_ip` playbook.
- `learn_from_db` treats every stored event as the normal baseline, including attacks from another `run_id`.
- `_finish` treats “no failed action and an empty verify list” as a case that may close, and drops the reporter’s `close` flag.
- `RuleEngine.process` treats a broken rule as “this event did not match,” with no fault row.

## External Research

Sigma’s condition language is a small grammar: `and`, `or`, `not`, parentheses, and `1 of` / `all of` over selection names ([Sigma condition specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md), [SigmaHQ conditions](https://sigmahq.io/docs/basics/conditions.html)). A recursive-descent parser that rejects anything else is the usual replacement for `eval`. pySigma is the reference compiler; a POC that only needs the operators its own rules use can keep a smaller parser, as long as a bad condition is a recorded fault and not a silent miss.

Other SOC-automation audits separate a published claim from the test that can fail it. A claim-to-gate matrix ties “every action is authorised” and “detection rate” to a check that inspects the real dispatch and the real rule body ([AiSOC claim-to-gate notes](https://github.com/beenuar/AiSOC/blob/main/docs/audit/CLAIM_TO_GATE_MATRIX.md)). A scoreboard that passes on a template, or on a global suite that never sees the rule under test, does not gate that claim. The same split is what `evaluate_soc` and the stream scoreboard do here: they grade a label that is upstream of containment.

## Recommendations

These are structural. They replace the split booleans and the skippable helpers. They are not local patches.

1. **One outcome record.** Every feed writes the same object: detector id, rule or baseline id, faults from detection, case id, verdict, each action’s tool and status, the tier the gate computed, and whether that action executed. `evaluate_soc`, the stream scoreboard, and the incident list read that object. “Detected” means an alert from a named detector. “Contained” means the expected tools are `executed`. A pending tier-2 action is a pass only when the scenario asks for `pending_approval`.

2. **Unknown detectors are faults.** A rule id or baseline id with no playbook binding does not select `malicious_ip`. The case escalates with the unbound id in the outcome. Adding a detector means adding the binding in the same change. `learn_from_db` filters on the run or the time window it was given; attacks from another run are not normal history.

3. **One clock for settling.** Replay, ingest, and stream share a settle record in SQLite keyed by activity (host, user, source IP). `flush()` moves that clock forward and then drains what is due. It does not skip the rule. `db.wipe()` clears the clock with the tables. Detector faults are rows in that same store, not a `continue` inside `RuleEngine.process`. Condition text is parsed, not evaluated.

4. **One place that mints a tier.** Delete `tier_override`. Vulnerability steps go through the same decision as SOC steps, with a playbook for VM remediation. `auto_if_high_confidence` becomes a reason inside that decision, not a branch that executes before approval. Submit of tier 2 or 3 without an approval record stays `pending_approval`. The per-alert LLM budget is charged only after a cache miss, and a missing `case_id` is a refused call rather than an unmetered one. `_finish` closes a case only when the outcome says every required action executed and verified; the reporter does not carry a second `close` flag.

5. **Tests that fail when a claim drifts.** One test per Sigma rule, including the five with no scenario today, asserting the outcome’s detector and action status. One ingest test that does not call `flush()` and still waits out the quiet window. One stream test that starts after a scenario run and does not treat that run as baseline. One test that a tier-2 step without approval is not `executed`. The README count and the stream steps point at this outcome, so a doc change is part of the same contract, not a separate edit.
