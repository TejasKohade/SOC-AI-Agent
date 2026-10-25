"""Orchestrator: a plain-Python state machine that moves each alert through
dedupe -> enrich -> triage -> investigate -> plan response -> act (via gate) -> verify -> report."""
import json
import re

from . import investigation, reporting, response, triage
from .base import AgentFailed, decode_powershell, injection_flags
from .investigation import _is_internal
from .. import config, db, inventory, soar
from ..tools import BudgetExceeded, ToolBox, http

OPEN = ("new", "triage", "investigating", "responding", "awaiting_approval", "verifying")
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_HOST = re.compile(r"https?://([^/:\s'\"]+)", re.I)


def get_case(case_id):
    c = db.one("SELECT * FROM cases WHERE id=?", (case_id,))
    if c:
        c["report"] = db.loads(c["report"], {}) or {}
        c["investigation_data"] = db.loads(c["investigation"], None)
    return c


def providers(case_id):
    """Which LLM backends answered this case's agents, e.g. {'bedrock': 3, 'offline': 1}."""
    out = {}
    for r in db.query("SELECT data FROM audit WHERE case_id=? AND kind='llm_response'", (case_id,)):
        p = (db.loads(r["data"], {}) or {}).get("provider", "?")
        out[p] = out.get(p, 0) + 1
    return out


def _set(case_id, **fields):
    db.update("cases", "id", case_id, {**fields, "updated": db.now()})
    if "status" in fields:
        db.audit(case_id, "orchestrator", "status", {"status": fields["status"]})


def _report_set(case_id, key, value):
    rep = get_case(case_id)["report"]
    rep[key] = value
    db.update("cases", "id", case_id, {"report": rep, "updated": db.now()})


def case_alerts(case_id):
    rows = db.query("SELECT * FROM alerts WHERE case_id=? ORDER BY ts", (case_id,))
    for r in rows:
        r["event_ids"] = db.loads(r["event_ids"], [])
        r["mitre"] = db.loads(r["mitre"], [])
        r["cves"] = db.loads(r["cves"], [])
    return rows


def case_events(alerts):
    ids = [i for a in alerts for i in a["event_ids"]]
    if not ids:
        return []
    rows = db.query(f"SELECT * FROM events WHERE id IN ({','.join('?' * len(ids))}) ORDER BY ts", ids)
    for r in rows:
        r["raw"] = db.loads(r["raw"], {})
    return rows


# ---------------- step 2-3: ingest, dedupe and group ----------------

def process_alert(alert, run_id=None, scenario=None):
    """Returns (case_id, merged: bool)."""
    since = db.now() - config.DEDUPE_WINDOW_S
    cond, args = [], []
    for col in ("host", "user"):
        if alert.get(col):
            cond.append(f"{col}=?")
            args.append(alert[col])
    existing = None
    if cond:
        # Group with any recent case on the same host/user. A case closed as a false positive only
        # absorbs alerts from the same rule, so a new real threat is never hidden behind it.
        for c in db.query(f"SELECT * FROM cases WHERE kind!='hunt' AND created>=? AND ({' OR '.join(cond)}) "
                          f"ORDER BY created DESC", (since, *args)):
            same_rule = db.one("SELECT 1 FROM alerts WHERE case_id=? AND rule_id=?", (c["id"], alert["rule_id"]))
            if c["status"] != "false_positive" or same_rule:
                existing = c
                break
    if existing:
        db.update("alerts", "id", alert["id"], {"case_id": existing["id"]})
        db.audit(existing["id"], "triage", "dedupe", {"alert": alert["id"], "rule": alert["rule_title"],
                                                      "merged_into": existing["id"]})
        return existing["id"], True

    case_id = "CASE-" + db.new_id("x")[2:].upper()
    db.insert("cases", {
        "id": case_id, "created": db.now(), "updated": db.now(),
        "title": f"{alert['rule_title']} on {alert['host'] or alert.get('user') or 'unknown'}",
        "status": "new", "severity": alert["severity"], "host": alert["host"], "user": alert["user"],
        "mitre": alert["mitre"], "run_id": run_id, "scenario": scenario, "kind": "alert", "report": {}})
    db.update("alerts", "id", alert["id"], {"case_id": case_id})
    db.audit(case_id, "orchestrator", "case_opened", {"alert": alert["id"], "rule": alert["rule_id"]})
    run_case(case_id)
    return case_id, False


# ---------------- step 4: enrich ----------------

def enrich(case, alerts, events):
    tb = ToolBox("orchestrator", case["id"])
    alert_ids = {i for a in alerts for i in a["event_ids"]}
    indicators = set()
    for e in events:
        r = e["raw"]
        for k in ("source.ip", "destination.ip"):
            if r.get(k) and not _is_internal(r[k]):
                indicators.add(str(r[k]))
        for k in ("url.domain", "url.full", "file.hash.sha256"):
            if r.get(k):
                indicators.add(str(r[k]))
        text = f"{r.get('process.command_line', '')} {decode_powershell(str(r.get('process.command_line', ''))) or ''}"
        indicators |= {ip for ip in IP.findall(text) if not _is_internal(ip)}
        indicators |= set(URL_HOST.findall(text))
    iocs = [tb.call("intel.lookup", indicator=i) for i in sorted(indicators)[:8]]
    host = tb.call("inventory.host", name=case["host"]) if case["host"] else None
    user = tb.call("inventory.user", name=case["user"]) if case["user"] else None
    findings = tb.call("vm.open_findings", host=case["host"]) if case["host"] else []
    similar = ToolBox("triage", case["id"]).call("cases.similar", rule_id=alerts[0]["rule_id"], host=case["host"])
    return {"iocs": iocs, "host": host, "user": user, "open_findings": findings, "similar": similar,
            "rules": [{"id": a["rule_id"], "title": a["rule_title"], "mitre": a["mitre"], "cves": a["cves"]} for a in alerts],
            "rule_ids": [a["rule_id"] for a in alerts], "alert_event_ids": sorted(alert_ids),
            "injection_flags": injection_flags(events)}


def triage_context(case, events, window=900, limit=25):
    """Events around the alert from the same user on the same host (or the host, if no user)."""
    if not events or not case["host"]:
        return []
    seen = {e["id"] for e in events}
    t0, t1 = min(e["ts"] for e in events) - window, max(e["ts"] for e in events) + window
    kw = {"host": case["host"], "since": t0, "until": t1, "limit": 200}
    if case["user"]:
        kw["user"] = case["user"]
    # skip repeats of what the alert already shows (e.g. 40 identical failed logins) so the
    # events that change the story, such as a later successful login, make it into the window
    shown = {(e["action"], e["src_ip"]) for e in events}
    rows = [r for r in ToolBox("triage", case["id"]).call("siem.search", **kw)
            if r["id"] not in seen and (r["action"], r["src_ip"]) not in shown]
    return rows[:limit]


def _evidence_sources(evidence, events):
    by_id = {e["id"]: e for e in events}
    src = set()
    for item in evidence:
        if item.startswith("intel:"):
            src.add("threat-intel")
        elif item in by_id:
            src.add(by_id[item]["source"] or "unknown")
    return src


# ---------------- steps 5-7 ----------------

def run_case(case_id, analyst_note=None):
    case = get_case(case_id)
    alerts = case_alerts(case_id)
    events = case_events(alerts)
    try:
        _set(case_id, status="triage")
        enr = enrich(case, alerts, events)
        linked = [f for f in enr["open_findings"] if f["cve"] in {c for a in alerts for c in a["cves"]}]
        if linked:
            _set(case_id, kind="incident", severity="critical",
                 title=f"INCIDENT: exploit attempt against open {linked[0]['cve']} on {case['host']}")
            db.audit(case_id, "orchestrator", "vm_link", {"findings": linked})
        elif any(f["priority"] in ("P1", "P2") for f in enr["open_findings"]):
            sev = {"low": "medium", "medium": "high", "high": "critical"}.get(case["severity"], case["severity"])
            _set(case_id, severity=sev)
            db.audit(case_id, "orchestrator", "severity_raised",
                     {"reason": "host has open P1/P2 vulnerabilities", "findings": enr["open_findings"]})
        case = get_case(case_id)

        # context events give triage the surrounding picture (e.g. the second half of a two-step attack)
        tri_events = events + triage_context(case, events)
        tri, meta = triage.run(case, tri_events, enr)
        tri["rules"] = enr["rule_ids"]
        _set(case_id, verdict=tri["verdict"], confidence=tri["confidence"], severity=tri["severity"]
             if not linked else "critical")
        _report_set(case_id, "triage", tri)
        _report_set(case_id, "enrichment", {k: enr[k] for k in ("iocs", "host", "user", "open_findings",
                                                                 "injection_flags")})
        if tri["verdict"] in ("false_positive", "benign"):
            return _finish(case_id, closing_status="false_positive")

        _set(case_id, status="investigating")
        inv, _ = investigation.run(get_case(case_id), alerts, events, analyst_note)
        db.update("cases", "id", case_id, {"investigation": inv,
                                           "mitre": sorted({m["id"] for m in inv.get("mitre", [])} |
                                                           set(json.loads(case["mitre"] or "[]")))})
        if inv.get("root_cause_cve") and case["host"]:
            from ..vm import lifecycle
            lifecycle.escalate_from_incident(case["host"], inv["root_cause_cve"], case_id)

        _set(case_id, status="responding")
        case = get_case(case_id)
        plan, _ = response.run(case, inv, enr["rule_ids"])
        _report_set(case_id, "plan", plan)
        _set(case_id, playbook=plan["playbook"])
        steps = soar.expand(plan["playbook"], plan["params"])
        ctx = {"verdict": tri["verdict"], "confidence": tri["confidence"],
               "host": plan["params"].get("host") or case["host"],
               "user": plan["params"].get("user") or case["user"],
               "target_user": plan["params"].get("target_user"),
               "evidence_sources": _evidence_sources(tri["evidence"], tri_events), "agent_raise": plan["raise_tier"]}
        if tri["verdict"] == "suspicious":
            ctx["agent_raise"] = {s["step"]: max(2, ctx["agent_raise"].get(s["step"], 0)) for s in steps}
        soar.submit(case_id, steps, ctx, playbook=plan["playbook"])
        for f in linked:
            from ..vm import lifecycle
            lifecycle.emergency_patch(f["id"], case_id)
        resume(case_id)
    except (AgentFailed, BudgetExceeded) as e:
        _set(case_id, status="escalated")
        db.audit(case_id, "orchestrator", "escalated", {"reason": str(e)})
    return case_id


def investigate_more(case_id, note, user="analyst"):
    db.audit(case_id, user, "investigate_more", {"note": note})
    case = get_case(case_id)
    alerts = case_alerts(case_id)
    try:
        inv, _ = investigation.run(case, alerts, case_events(alerts), note)
        db.update("cases", "id", case_id, {"investigation": inv})
    except (AgentFailed, BudgetExceeded) as e:
        db.audit(case_id, "orchestrator", "escalated", {"reason": str(e)})


# ---------------- steps 8-10: act, verify, report ----------------

def resume(case_id):
    """Called after the plan is submitted and after every approval decision."""
    case = get_case(case_id)
    if not case or case["status"] in ("closed", "false_positive"):
        return
    if soar.pending(case_id):
        _set(case_id, status="awaiting_approval")
        return
    _finish(case_id)


def verify(case_id):
    checks = []
    for a in case_actions(case_id):
        if a["status"] != "executed":
            continue
        p, ok, detail = a["params"], True, "executed"
        if a["tool"] == "edr.isolate_host":
            ok = http().get(f"/edr/hosts/{p['host']}").json()["isolated"]
            detail = "host isolated" if ok else "host NOT isolated"
        elif a["tool"].startswith("firewall.block"):
            blocked = {b["target"] for b in http().get("/firewall/blocked").json()}
            ok = p["indicator"] in blocked or any(t.endswith(":" + str(p["indicator"])) for t in blocked)
            after = db.query("SELECT id FROM events WHERE (src_ip=? OR dst_ip=? OR raw LIKE ?) AND ts>?",
                             (p["indicator"], p["indicator"], f"%{p['indicator']}%", a["updated"]))
            ok = ok and not after
            detail = f"blocked; {len(after)} new events from indicator since the block"
        elif a["tool"] == "idp.disable_user":
            ok = http().get(f"/idp/users/{p['user']}").json()["disabled"]
            detail = "account disabled" if ok else "account still enabled"
        checks.append({"action": a["id"], "tool": a["tool"], "verified": bool(ok), "detail": detail})
    return {"checks": checks, "all_verified": all(c["verified"] for c in checks)}


def case_actions(case_id):
    return [soar.get(r["id"]) for r in db.query("SELECT id FROM actions WHERE case_id=? ORDER BY created",
                                                (case_id,))]


def _finish(case_id, closing_status=None):
    _set(case_id, status="verifying")
    case = get_case(case_id)
    acts = case_actions(case_id)
    ver = verify(case_id)
    _report_set(case_id, "verification", ver)
    try:
        rep, _ = reporting.run(case, case["investigation_data"], acts, ver, case["report"].get("triage", {}))
    except (AgentFailed, BudgetExceeded) as e:
        _set(case_id, status="escalated")
        db.audit(case_id, "orchestrator", "escalated", {"reason": f"reporting failed: {e}"})
        return case_id
    _report_set(case_id, "final", rep)
    _write_tuning(case, rep)
    problems = any(a["status"] == "failed" for a in acts) or not ver["all_verified"]
    if closing_status == "false_positive":
        _set(case_id, status="false_positive", summary=rep["executive_summary"])
    elif problems:
        _set(case_id, status="escalated", summary=rep["executive_summary"])
    else:
        _set(case_id, status="closed", summary=rep["executive_summary"])
    return case_id


def _write_tuning(case, rep):
    if not rep.get("rule_tuning"):
        return
    d = config.TUNING_DIR / "suggestions"
    d.mkdir(parents=True, exist_ok=True)
    lines = [f"# Rule tuning from {case['id']}", "", f"Case: {case['title']}  ", f"Verdict: {case['verdict']}", ""]
    for t in rep["rule_tuning"]:
        lines.append(f"- **{t.get('rule_id', '?')}**: {t['suggestion']}")
    (d / f"{case['id']}.md").write_text("\n".join(lines) + "\n")
