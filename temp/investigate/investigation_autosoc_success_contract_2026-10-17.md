# Investigation: AutoSOC success contract

**Date:** 2026-10-17
**Scope:** What the README, the stream demo, the scoreboard, and the scenario tests each count as a successful detection, checked against the current code. The earlier reports covered the three feeds and the skippable approval gate. This one is about the words those feeds use for “caught.”

## Summary

AutoSOC now publishes one story and runs three measurements. The README says every event is categorised, matched by Sigma and by behaviour baselines, grouped into a scored incident, and then answered by that severity through the approval gate. The code categorises on every store, runs baselines only inside `StreamEngine`, scores an incident from the case verdict, and authorises actions from the playbook tier. “Detected” means an alert existed in a scenario check, and a non-benign verdict in the stream scoreboard. Neither check asks whether a containment action executed. Four Sigma rules and every baseline id have no playbook, so the offline responder falls through to `malicious_ip`. Tuning notes are written when a case closes and nothing reads them back. The suite is 33 tests; the README still says 29.

## Root Cause

There is no single result type. Each surface invented a boolean or a label for a different row.

- Scenario success is `evaluate_soc` in `autosoc/pipeline.py`. `detected` is `bool(alerts)`. Expected actions match any row with that tool name, including `pending_approval`. Only `status == "executed"` is checked for unexpected tools.
- Stream success is `_match_ground_truth` in `autosoc/stream/engine.py`. An injection is detected when it is linked to a case whose verdict is not `false_positive` or `benign`. The scoreboard never reads `actions` or `mock_state`.
- Incident “intel confirmation” is `any(verdict == "malicious")` in `autosoc/incidents.py` `severity_score`. The rationale string says `intel-confirmed`. Threat-intel hits are not an input. The score does not choose a tier.
- The README’s step “Respond by severity” describes the approval gate. `soar.submit` uses the playbook step and `compute_tier`, or `tier_override` when the caller supplies one. `severity_score` is a sort key for `list_open`.
- Unmapped detectors are not a fault. `response._offline` maps rule id to playbook and, if none matches, uses `"malicious_ip"`. Baseline ids (`baseline-new-location`, `baseline-rare-process`, and the rest) and four Sigma ids (`autosoc-account-created`, `autosoc-remote-exec`, `autosoc-lolbin-exec`, `autosoc-lsass-access`) take that default.
- `Baselines.learn_from_db` accepts `run_id` and ignores it. The query is every row in `events`. A stream engine started after a scenario run learns that run’s attacks as normal.

The approval-gate skips from the earlier investigation are still in place (`tier_override`, `auto_if_high_confidence` on the malware playbook, `case_id` missing, hunt LLM exemption, reporting `close` ignored by `_finish`). They are a second contract failure: the gate is a helper, and the scoreboard cannot see whether it held.

## Affected Components

- `README.md`: the asyncio diagram, the “29 tests” line, stream steps 1–5, and the sentence that everything after ingest matches the scenario path.
- `DEMO_streaming.md`: demo timing and the same severity story. Stream settle is 6 seconds quiet / 45 seconds max (`autosoc/stream/engine.py`). Ingest settle is 10 / 120 (`autosoc/ingest.py`). No test measures the “about 20–30 seconds” claim.
- `autosoc/pipeline.py`: scenario oracle.
- `autosoc/stream/engine.py`: stream oracle, baselines, warmup (store and observe, no detection), incident correlation only on this feed.
- `autosoc/detect/baseline.py`: second detector; `learn_from_db` is unscoped.
- `autosoc/incidents.py`: severity score and the `intel-confirmed` label.
- `autosoc/agents/response.py`: playbook fallback.
- `autosoc/agents/orchestrator.py`: `_finish` writes tuning files and sets case status from actions and verify, not from the report’s `close` flag.
- `playbooks/*.yml`: eight playbooks, each bound to one Sigma id. `data_exfiltration` is the only base tier 3.
- `siem/rules/*.yml`: twelve rules. Five have no scenario file: account created, remote exec, LOLBin, LSASS access, data exfiltration.
- `tests/test_stream.py`, `tests/test_scenarios.py`, `tests/test_ingest.py`: the three oracles. Ingest and stream tests drain with `flush()` or `_work(now=float("inf"))`.
- `tuning/suggestions/*.md`: output of `_write_tuning`. No reader under `siem/` or `playbooks/`.

## Data Flow

Replay builds a fresh `RuleEngine`, stores every event (which always categorises), matches Sigma only, then calls `process_alert` after the whole window. `run_id` is a new id. Success is the YAML `expect` block.

Live ingest uses one process-wide `RuleEngine`, `run_id` `"live"`, and a settle queue. It does not call `Baselines`. The HTTP handler returns before the agents run. `flush()` treats the quiet window as already elapsed.

Stream uses `run_id` `"stream"`, a new rule engine plus a baseline model, and a shorter settle clock. `_detect` is `rules.process` then `baselines.ask` then `baselines.observe`, so the current event does not train the check that just ran. Warmup stores and observes and does not detect. After `process_alert`, a non-benign case is passed to `incidents.correlate`, then the injection row is marked from the verdict.

All three still end in `run_case`: triage, investigate, response plan, `soar.submit`. Tier 0–1 executes immediately. Tier 2 executes without a person only when `auto_if_high_confidence` is set, the verdict is malicious, confidence is at least 0.95, and `compute_tier` added no reasons. That flag is on `kill_process` and `isolate_host` in `playbooks/malware_endpoint.yml`. Tier 3 (`firewall.block_ip` in `playbooks/data_exfiltration.yml`) needs an analyst and a SOC lead.

`db.wipe()` clears tables and does not call `ingest.reset()`. The live rule-engine windows and the settle queue stay in memory. `learn_from_db` will treat whatever remains, or whatever was just replayed, as the baseline.

## Test Gap Analysis

Sixteen test functions expand to 33 pytest items. `conftest.py` forces the offline model and wipes the database. It does not reset the ingest singleton.

The tests miss the contract because each oracle checks the boolean it invented:

- `test_soc_scenario` asserts `pipeline.run()["passed"]`. A schtask case can pass with `edr.isolate_host` still `pending_approval`, because the tool name is on the row and `max_tier` reads `policy_tier`. Only `test_approval_closes_the_loop` approves three of the eight SOC scenarios and checks `closed`.
- `test_ingest_triggers_bruteforce_across_requests` calls `flush()` and checks tool names, not `executed`, and not the 10-second quiet window. Only `ssh-bruteforce-01` is compared to replay.
- `test_stream_detects_injected_attacks` calls `_work(now=float("inf"))` and requires `detection_rate >= 0.75` and at least five real injections detected. A suspicious verdict with no executed action counts. Impossible-travel is a baseline alert, so a pass does not prove a Sigma rule fired. The five Sigma ids with no scenario are not named in any assertion.
- Nothing reads `tuning/suggestions`, the scheduler, `tools/send_logs.py`, the UI, or a real model. Nothing asserts that `severity_score` changes a tier, because it does not.

A green run is compatible with a planned tier-2 action, a baseline alert answered by the brute-force playbook, and a scoreboard that never looked at the firewall.

## Similar Patterns

The same shape shows up wherever a check is a label a caller can satisfy without the underlying fact.

| Word in the docs or UI | Fact the word suggests | Fact the code uses |
|---|---|---|
| Detected (scenario) | The attack was handled | At least one alert row |
| Detected (scoreboard) | The injection was caught and answered | Case verdict is not false-positive or benign |
| Intel-confirmed | A threat-intel hit | Some case verdict is `malicious` |
| Respond by severity | The 0–100 score drives the gate | Playbook tier, or `tier_override` on VM patches |
| Identical after ingest | Replay and live share detectors and timing | Both call `process_alert`. Baselines and the settle clock do not |
| Rule tuning | A closed loop into the rule | A markdown file under `tuning/suggestions/` |
| 29 tests | The suite that locks the above | 33 items, and the new ones use the loose oracles |

`_finish` ignoring `close`, `tickets_api()` posting outside `soar.execute`, and `ToolBox("triage")` built by the orchestrator are the same class on the way out: a step that looks governed and is not on the path that runs.

## External Research

MITRE ATT&CK Evaluations keep detection and protection as separate scores, and they publish investigation quality beside that sum rather than inside it. A scenario can investigate well after a weak technique detection, and a detection is not a block. Collapsing those into one rate hides which layer failed. Sources: [methodology specification](https://evals.mitre.org/methodology-specification), [detection categories](https://evals.mitre.org/enterprise/er6/detection-categories). The detection phase is run with protection off; the protection phase records whether the behavior was blocked and how far it got ([Palo Alto Networks write-up of the 2024 split](https://www.paloaltonetworks.com/blog/security-operations/mitre-attck-2024-raising-the-bar-for-security-testing/)).

AutoSOC’s scoreboard is closer to a detection-phase rate, except the predicate is the agent’s verdict, not a documented detection criterion for the technique. The scenario checker is closer to a protection claim, except a pending action satisfies it. The incident score is a third number that neither oracle reads, and the UI ranks on it while the gate ignores it.

## Recommendations

These are structural, not text edits and not a softer fallback when a detector misses.

1. **One result record per attack.** For each scenario and each stream injection, store separate fields: which detector fired (Sigma rule id or baseline id), whether a case opened, the verdict, the incident score, and each action’s status. Delete the shared word “detected” from both oracles. `evaluate_soc` and `scoreboard` read that record. A rate is a view over it, not the thing the test asserts. A technique with no detection criterion cannot be in the denominator.

2. **One pipeline object, three clocks only if the object says so.** Replay, ingest, and stream should call the same function for store, detect, settle, and `process_alert`. Baselines are either inside that function for every feed or a named stage that ingest and replay do not pretend to run. `learn_from_db` filters on the `run_id` it is given; an omitted run id is an error, not “all events.” `db.wipe` and that pipeline’s `reset` are one operation.

3. **Severity ranks. The gate authorises.** `severity_score` stays a sort key. It does not grant execution, and its rationale names the verdict bump as a verdict bump. Threat intel is a separate input if a later design wants a confirmation term. `response` refuses a detector id that is not listed on exactly one playbook. There is no default playbook. Baseline ids get playbooks, or they cannot open a response.

4. **Tuning is a review queue with a single writer.** A suggestion is a proposed diff against a rule file. Applying it is an explicit accept that changes `siem/rules` and is then covered by the result record in (1). A markdown file that no loader reads is not that queue. Do not keep writing suggestions that cannot affect the next match.

5. **The documented contract is generated from those types.** The test count, the settle bounds, and the detector list in the README are outputs of the pipeline object and the result record. A hand-maintained “29 tests” line will drift again the next time a feed is added.
