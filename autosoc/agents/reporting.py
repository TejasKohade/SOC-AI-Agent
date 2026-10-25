"""Reporting agent: writes the case report, lessons learned and rule-tuning suggestions."""
import json

from . import base

TASK = """ROLE: SOC reporting analyst.
Write the final case report from the case record. Return JSON:
{"title": "short case title",
 "executive_summary": "3-5 sentences for a manager: what happened, impact, what was done",
 "report_markdown": "full report in Markdown: Summary, Timeline, Scope, Actions taken (with tiers and who approved), Verification, Recommendations",
 "lessons_learned": ["..."],
 "rule_tuning": [{"rule_id": "...", "suggestion": "..."}],
 "close": true or false,   // false if anything still needs a human (pending, rejected or failed actions, or unverified containment)
 "close_reason": "one sentence"}"""


def _offline(case, inv, actions, verification, triage):
    acted = [f"- `{a['tool']}` {json.dumps(a['params'])} — tier {a['tier']}, **{a['status']}**" for a in actions]
    ok = all(a["status"] == "executed" for a in actions) and verification.get("all_verified", True)
    tuning = []
    if triage.get("rule_tuning"):
        tuning.append({"rule_id": (triage.get("rules") or ["?"])[0], "suggestion": triage["rule_tuning"]})
    md = "\n".join([
        f"## Summary\n{(inv or {}).get('summary') or triage.get('reasoning', '')}",
        f"\n## Verdict\n{case['verdict']} (confidence {case['confidence']:.2f})",
        "\n## Timeline", *[f"- {t['time']} `{t['event_id']}` {t['description']}" for t in (inv or {}).get("timeline", [])],
        "\n## Actions taken", *(acted or ["- none"]),
        f"\n## Verification\n{json.dumps(verification)}",
    ])
    return {"title": case["title"], "executive_summary": (inv or {}).get("summary") or triage.get("reasoning", ""),
            "report_markdown": md, "lessons_learned": [], "rule_tuning": tuning, "close": ok,
            "close_reason": "All actions executed and verified." if ok else "Some actions were not executed."}


def run(case, investigation, actions, verification, triage):
    def validate(o):
        base.need(o, "executive_summary", str)
        base.need(o, "report_markdown", str)
        o["close"] = bool(o.get("close"))
        o.setdefault("lessons_learned", [])
        o.setdefault("rule_tuning", [])
        o["rule_tuning"] = [t for t in o["rule_tuning"] if isinstance(t, dict) and t.get("suggestion")]
        return o

    inv = {k: v for k, v in (investigation or {}).items() if k != "facts"}
    payload = "\n".join([
        f"CASE: {json.dumps({k: case[k] for k in ('id', 'title', 'severity', 'host', 'user', 'verdict', 'confidence')})}",
        f"TRIAGE: {json.dumps(triage)}",
        f"INVESTIGATION: {json.dumps(inv)}",
        f"ACTIONS: {json.dumps([{k: a[k] for k in ('tool', 'params', 'tier', 'status', 'approvals', 'tier_reasons')} for a in actions])}",
        f"VERIFICATION: {json.dumps(verification)}",
    ])
    return base.run("reporting", case["id"], TASK, payload, validate,
                    lambda: _offline(case, investigation, actions, verification, triage))
