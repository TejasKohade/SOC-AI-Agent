# Investigation: AutoSOC codebase

**Date:** 2026-10-17
**Scope:** Whole repository at `/Users/tejaskohade/Documents/Cybergate`. Module investigation of how the POC is structured, where its safety properties are actually enforced, and why the test suite cannot see the gaps. No single error or traceback was supplied.

## Summary

AutoSOC is a single-process SOC and vulnerability-management proof of concept. Scenarios become events, a small Sigma-style engine writes alerts into SQLite, and `orchestrator.run_case` runs triage, investigation, response, a playbook approval gate, mock tools, verification, and reporting in one thread. Vulnerability management shares that database and the same gate, but builds remediation steps in Python instead of playbook YAML. The design separates reasoning from actuation for the SOC agent path: agents may only read, and `soar.execute` is the only caller of state-changing mock APIs. That separation is a call-graph convention. Budgets, evidence rules, prompt wrapping, tier raises, and detection failures each live in one function that another caller can skip (`case_id=None`, `tier_override`, a bare `except`, or the offline provider). The 26 tests lock the offline stand-in and the scenario oracles together, so they pass while live-provider behavior, gate side doors, and swallowed rule errors stay unenforced.

## Root Cause

There is no single defect. The structural source of the gaps is that each guardrail is a check inside a helper, and the type of the system does not require every caller to pass through that helper.

- LLM budget is incremented in `agents/base.py` `_use_budget` only when `case_id` is set, and hunt cases are exempt. `vm_agent.run` and `weekly_report` call `base.run` with `case_id=None`, so those calls never touch the cap. The increment happens before `llm.complete_json`, so a cache hit still consumes a slot.
- Approval policy is `soar.compute_tier`, except `soar.submit` prefers `tier_override` when present. `vm/lifecycle.py` `plan_remediation` always sets that override, so VM patches never receive the confidence, asset, or evidence raises.
- Detection failures are discarded. `siem.RuleEngine.process` catches every exception per rule and continues, with no audit row.
- Closure policy is `orchestrator._finish` (failed actions and `verify`). The reporting agent's `close` field is validated and then ignored.

These are the same shape: a policy function exists, and a second path produces the same kind of effect without it.

## Affected Components

- `autosoc/pipeline.py`: SOC replay (`run_soc`, `_replay`, `evaluate_soc`) and the VM step interpreter (`run_vm`). Also the place scenario YAML becomes the test oracle.
- `autosoc/telemetry.py`: scenario YAML to ECS-like events, fixed seed.
- `autosoc/siem.py`: rule load, selection matching, boolean `eval` of the condition, threshold windows. Silent skip on match errors.
- `autosoc/agents/orchestrator.py`: dedupe, enrich, case state machine, verify, finish. Imports VM lifecycle for incident side effects and borrows `ToolBox("triage")` for similar-case and SIEM search.
- `autosoc/agents/base.py`: shared LLM wrapper, untrusted wrapping, LLM budget, offline retry skip.
- `autosoc/agents/triage.py`, `investigation.py`, `response.py`, `reporting.py`, `vm_agent.py`: per-agent schema checks. Evidence and parameter grounding exist only inside triage and response validators.
- `autosoc/soar.py`: playbook catalogue, tier computation, submit, execute, approve, rollback. Runtime imports back into orchestrator and VM lifecycle after a decision.
- `autosoc/vm/lifecycle.py` and `autosoc/vm/scoring.py`: scan, score, ticket, remediate, SLA, exceptions. Remediation tiers are Python, not YAML.
- `autosoc/llm.py`: Bedrock then OpenRouter, then the offline callable. Cache, quota flags, HTTP retry.
- `autosoc/tools.py` and `autosoc/mocks/app.py`: read allowlists and the in-process mock client. `ResponseClient` is the state-changing boundary.
- `autosoc/db.py`: one SQLite file for events, alerts, cases, actions, findings, tickets, audit, cache, and metrics.
- `ui/app.py`: Streamlit over `db`, `soar`, `orchestrator`, and `lifecycle` with no service façade.
- `tests/test_scenarios.py`, `tests/test_guardrails.py`, `tests/conftest.py`: offline provider, temp database, scenario `expect` blocks.
- `siem/rules/data_exfiltration.yml` and `playbooks/data_exfiltration.yml`: rule and playbook with no scenario under `scenarios/soc/`.
- `README.md`: the only architecture document. Describes Gemini and Groq in the provider chain; `llm.py` implements only Bedrock and OpenRouter.

## Data Flow

SOC path:

1. `pipeline.run_soc` loads a scenario and `telemetry.generate` expands events.
2. `_replay` pushes events through an asyncio queue into `siem.store_event` and `RuleEngine.process`, then `store_alert`.
3. After ingest, each alert is handled synchronously by `orchestrator.process_alert` (15-minute dedupe on host or user, then `run_case`).
4. `run_case` enriches with intel, inventory, open findings, and injection flags, then calls triage. A benign or false-positive verdict finishes the case without investigation or response.
5. Otherwise investigation pivots through `ToolBox`, response selects a playbook, and `soar.submit` records actions. Tier 0–1 executes immediately. Tier 2 executes immediately when `auto_if_high_confidence` is set, the verdict is malicious, confidence is at least 0.95, and `compute_tier` recorded no raise reasons. Everything else waits.
6. `execute` calls `ResponseClient`, which hits the FastAPI mocks in-process unless `MOCK_BASE_URL` is set.
7. Approval or rejection re-enters `orchestrator.resume` from `soar._after_decision`. When nothing is pending, `_finish` verifies mock state and writes the report.

VM path:

1. `pipeline.run_vm` interprets a step list (`job`, `approve`, `advance`, nested `soc`, `expect`).
2. `lifecycle.run_scan` scores catalogue CVEs with `scoring.risk` (`CVSS × asset weight × exposure weight + 3·KEV + 5·EPSS`).
3. `vm_agent.run` writes a summary with no case id, so the SOC LLM cap does not apply.
4. `plan_remediation` builds a `patch.apply` step, stamps `tier_override`, and submits it as playbook name `vm_remediation`. There is no `playbooks/vm_remediation.yml`.
5. The same `ResponseClient` path runs the patch. `lifecycle.on_action_done` updates the finding.

Both paths share `db.conn`, `llm_cache`, and `mock_state`. The UI and the CLI call those modules directly.

## Test Gap Analysis

`tests/conftest.py` forces `LLM_PROVIDER=offline` and wipes the database before every test. The 26 tests are 6 guardrail checks plus 17 scenario runs plus 3 auto-approve closure checks.

What the suite actually locks in:

- `scoring.risk` / `priority` for four numeric examples.
- `base.wrap` on one injection string.
- `ToolBox` denial for two disallowed calls.
- Triage `validate` rejecting a fake event id when `complete_json` is monkeypatched (two budget increments, live-provider retry path).
- `compute_tier` does not lower a requested tier 3, low confidence raises tier 1 to 2, and tier 3 needs two roles and two users.
- Every scenario YAML `expect` block, evaluated inside `pipeline.evaluate_soc` / `run_vm` `_check`.

What those tests treat as success:

- A SOC scenario passes when the planned tool names match `expect.actions`. Tier 2 and 3 actions may still be `pending_approval`. Only `ssh-bruteforce-01`, `encoded-powershell-01`, and `schtask-persistence-01` are required to close, and only with `auto_approve=True`.
- Verdicts come from the offline heuristics in each agent, which key off the same rule ids and intel hits the scenarios were written around. The oracle and the implementation were designed together.
- `evaluate_soc` drops agent-only tier raises out of the `max_tier` check, so an agent that raises the displayed tier does not fail the scenario.

Absent from the suite: `llm.py` provider failover, cache accounting, scheduler, Streamlit, `MOCK_BASE_URL`, `tier_override`, `auto_if_high_confidence`, `raise_if`, single-source and critical-asset raises, reject, `escalate_stale`, LLM and tool budget exhaustion, hunt exemption, SIEM match errors, the data-exfiltration rule, and reporting `close` versus orchestrator closure.

The tests assume the offline stand-in is the product. A change to `_offline` can satisfy `expect.verdict` while Bedrock or OpenRouter output remains unconstrained beyond the per-agent `validate` functions.

## Similar Patterns

Sound pattern, used on the SOC response path: the agent returns a plan, `soar.submit` freezes tier and parameters on the `actions` row, and only `ResponseClient` performs the POST. Rollback is stored with the action. This matches the usual human-in-the-loop split (read and reason freely, gate actuation). Industry write-ups describe the same boundary: Sigma (or an equivalent) detects, a deterministic playbook binds parameters, and irreversible steps wait for a named approver ([UnderDefense HITL SOC design](https://underdefense.com/blog/human-in-the-loop-soc-design/), [Splunk SOAR approval playbook](https://lantern.splunk.com/Security_Use_Cases/Automation_and_Orchestration/Building_a_SOAR_playbook_for_user-initiated_approval_of_automation), [LimaCharlie human-in-the-loop response](https://docs.limacharlie.io/5-integrations/tutorials/human-in-the-loop-response/)).

The same shape is not used everywhere:

| Concern | Path that enforces it | Path that does not |
|---|---|---|
| Actuation | `soar.execute` → `ResponseClient` | Mock HTTP is still a public FastAPI app; any `MOCK_BASE_URL` client can POST. VM tickets use `tickets_api()` directly. |
| Tiers | Playbook YAML `tier` plus `compute_tier` raises | `plan_remediation` `tier_override`; suspicious verdict forces tier 2 in the orchestrator via `agent_raise` |
| Evidence | `triage.validate` for event ids and `intel:` tokens; `response.validate` for parameters present in facts | Investigation IOC fields are prompt-only. Reporting `close` is not a gate. |
| Budgets | `ToolBox.call` and `_use_budget` when `case_id` is set and `kind != "hunt"` | `case_id=None` (VM agent, weekly report); cache hit counted before lookup |
| Detection | `RuleEngine.process` alerts on a match | Any exception, including an unknown selection, is `continue` with no audit |
| Contracts | VM steps raise `ValueError` on an unknown op | Rules, playbooks, and SOC scenarios have no schema at load. `_render` drops a step when a template value is missing. |

`data_exfiltration` is the detection twin of a missing scenario: rule and playbook exist, `response.py` has an offline branch for that playbook id, and `scenarios/soc/` has no file that fires it.

## External Research

- Sigma conditions are a small expression language (`and` / `or` / `not` / `1 of` / `all of them`), meant to be interpreted, not executed as host code. Correlation and filters are separate rule types. AutoSOC reimplements a subset and finishes with `eval` on a token string that is supposed to contain only booleans and those operators. A parser with an explicit AST would make an illegal token a load error instead of a skipped event. Source: [Sigma specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md).
- HITL SOC design treats tiering as a property of the action (reversible versus irreversible), applied by one control, with uncertainty always raising the tier. AutoSOC's numeric tiers live in YAML for SOC and in `remediation_tier()` for VM, and `auto_if_high_confidence` lowers a tier-2 step to automatic when confidence is high. Source: [Human in the Loop SOC Design](https://underdefense.com/blog/human-in-the-loop-soc-design/).
- Playbook authoring practice puts rollback on every actuating step and keeps approval as data on the step, not as a Python override. AuroraSOC's model is one YAML schema for trigger, step class, and `rollback_action`. AutoSOC's SOC playbooks follow that idea; VM remediation does not. Source: [AuroraSOC SOAR playbook authoring](https://docs.aurorasoc.ahmeddwalid.me/docs/user/runbooks/soar-playbook-authoring).
- The cited product spec *AutoSOC: End-to-End SOC Automation POC* is not in the repository. `README.md` is the spec the code is compared against, and it still documents a Gemini and Groq fallback chain that `llm.py` does not implement (`PROVIDERS = ("bedrock", "openrouter")`).

## Recommendations

These are architectural directions. They are not patches.

1. **One policy object for actuation.** Every state-changing step, SOC or VM, should be a playbook step interpreted by `compute_tier` and `submit`. Delete the ability to stamp a finished tier from lifecycle code. VM maintenance windows and asset class become inputs the gate reads, the same way `raise_if` and criticality already are. `auto_if_high_confidence` becomes a documented tier rule in that same function, or it goes away. High confidence must not be a second, quieter gate.

2. **Budgets and evidence as entry requirements, not optional arguments.** The LLM client should refuse a completion that lacks a budget scope. Hunt and VM get their own scopes with their own caps, created by the case/finding constructor, so `None` is not a bypass. Count a call only when a provider runs; a cache hit is not a call. Evidence rules (event ids, intel hits, response parameters grounded in facts) should be one validator applied to every agent result before it is stored, not a private `validate` inside triage and response.

3. **Detection contracts fail closed and in the open.** Load rules, playbooks, and scenarios through a schema. A rule that does not parse does not join the engine. A match error writes an audit record and an operator-visible failure for that rule, and still processes the other rules. Replace condition `eval` with a boolean parser. A scenario file is required for every rule id, so `autosoc-data-exfiltration` cannot exist only as YAML the suite never runs.

4. **Tests that own the invariant, separate from the scenario story.** Keep the scenario runs. Add tests whose expected value is the policy, not the offline heuristic: tier monotonicity for every playbook step including VM remediation, budget exhaustion including cache hits and hunt/VM scopes, a rule that throws during match, a missing template parameter, and a recorded provider transcript that is not `_offline`. `pipeline.evaluate_soc` should stop being both the product metric and the assertion. The test reads case, action, and audit rows and decides pass or fail itself.

5. **Replace the callback cycle with a case event.** `soar._after_decision` currently imports `orchestrator.resume` and `lifecycle.on_action_done`. Approval, verification, and finding updates should subscribe to "action decided" without the playbook module importing the case machine. The UI should call that same application surface instead of `db.query` / `db.wipe` / `soar.approve` as separate doors.

6. **Make the README the generated description of `llm._providers` and the gate**, or generate the provider list from code. A documented Gemini/Groq chain that the process cannot call is a contract the rest of the system is not allowed to have.
