"""Triage agent: verdict + confidence for a case, with evidence that must exist."""
import json

from . import base

VERDICTS = {"false_positive", "benign", "suspicious", "malicious"}
SEVERITIES = {"low", "medium", "high", "critical"}

TASK = """ROLE: Tier-1 triage analyst.
Decide whether the alert group is a real threat. Use the detection rule, the raw events, threat-intel
enrichment, asset and user context, open vulnerabilities on the host, and similar past cases.
Return JSON:
{"verdict": "false_positive|benign|suspicious|malicious",
 "confidence": 0.0-1.0,
 "severity": "low|medium|high|critical",
 "reasoning": "2-4 sentences",
 "evidence": ["<event_id from the input>" or "intel:<indicator that intel marked malicious>", ...],
 "rule_tuning": "if false_positive/benign: one concrete rule-tuning suggestion, else empty string"}
A "malicious" verdict MUST cite at least one evidence item. Known-good admin tooling (for example a
software-deployment agent as the parent process, with no malicious intel hits) is usually a false positive."""

ALLOWLISTED_PARENTS = {"ccmexec.exe", "intunemanagementextension.exe", "ansible", "puppet"}


def _offline(case, events, enrich):
    """Deterministic stand-in used without an LLM (tests, outages)."""
    bad = [i for i in enrich["iocs"] if i.get("verdict") == "malicious"]
    ev_ids = [e["id"] for e in events if e["id"] in set(enrich["alert_event_ids"])][:10]
    rule = enrich["rule_ids"][0] if enrich["rule_ids"] else ""
    parents = {str(e["raw"].get("process.parent.name", "")).lower() for e in events
               if e["id"] in set(enrich["alert_event_ids"])}
    evidence = ev_ids + [f"intel:{i['indicator']}" for i in bad]
    if parents & ALLOWLISTED_PARENTS and not bad:
        return {"verdict": "false_positive", "confidence": 0.9, "severity": "low",
                "reasoning": "Command launched by a software-deployment agent with no malicious intel hits.",
                "evidence": ev_ids, "rule_tuning": f"Exclude parent processes {sorted(parents & ALLOWLISTED_PARENTS)} "
                                                 f"signed by the deployment service from {rule}."}
    if bad or rule in ("autosoc-credential-dumping",):
        return {"verdict": "malicious", "confidence": 0.96, "severity": "high" if rule != "autosoc-credential-dumping" else "critical",
                "reasoning": f"Rule {rule} fired and {len(bad)} indicator(s) are known-malicious in threat intel.",
                "evidence": evidence, "rule_tuning": ""}
    if rule in ("autosoc-new-local-admin", "autosoc-schtask-persistence", "autosoc-exploit-attempt"):
        return {"verdict": "malicious", "confidence": 0.86, "severity": "high",
                "reasoning": f"Rule {rule} matched behaviour with no legitimate change ticket or admin context.",
                "evidence": evidence, "rule_tuning": ""}
    return {"verdict": "suspicious", "confidence": 0.6, "severity": "medium",
            "reasoning": "Rule matched but no corroborating intel; needs an analyst.", "evidence": evidence,
            "rule_tuning": ""}


def run(case, events, enrich):
    valid_ids = {e["id"] for e in events}
    bad_iocs = {i["indicator"].lower() for i in enrich["iocs"] if i.get("verdict") == "malicious"}

    def validate(o):
        base.need(o, "verdict", str, VERDICTS)
        c = float(base.need(o, "confidence"))
        if not 0 <= c <= 1:
            raise ValueError("confidence must be between 0 and 1")
        o["confidence"] = c
        o["severity"] = o.get("severity") if o.get("severity") in SEVERITIES else case["severity"]
        ev = base.need(o, "evidence", list)
        cleaned = []
        for item in ev:
            item = str(item)
            if item.startswith("intel:"):
                if item[6:].lower() not in bad_iocs:
                    raise ValueError(f"evidence {item} is not a malicious intel hit in the input")
            elif item not in valid_ids:
                raise ValueError(f"evidence {item} is not an event id in the input")
            cleaned.append(item)
        if o["verdict"] == "malicious" and not cleaned:
            raise ValueError("a malicious verdict must cite evidence")
        o["evidence"] = cleaned
        o.setdefault("reasoning", "")
        o.setdefault("rule_tuning", "")
        return o

    payload = "\n".join([
        f"CASE: {case['title']} (severity {case['severity']})",
        f"RULES FIRED: {json.dumps(enrich['rules'])}",
        f"ASSET: {json.dumps(enrich['host'])}",
        f"USER: {json.dumps(enrich['user'])}",
        f"THREAT INTEL: {json.dumps(enrich['iocs'])}",
        f"OPEN VULNERABILITIES ON HOST: {json.dumps(enrich['open_findings'])}",
        f"SIMILAR PAST CASES: {json.dumps(enrich['similar'])}",
        f"PROMPT-INJECTION FLAGS: {json.dumps(enrich['injection_flags'])}",
        "EVENTS (alert events first, then surrounding context):",
        base.present_events(events),
    ])
    return base.run("triage", case["id"], TASK, payload, validate, lambda: _offline(case, events, enrich))
