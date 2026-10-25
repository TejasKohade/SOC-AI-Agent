"""Vulnerability management cycle: discover -> scan -> score -> track -> VM agent -> ticket ->
remediate (via the SOC approval gate) -> verify by rescan, plus SLA, exception and KEV jobs."""
import hashlib
import json
import re

from . import scoring
from .. import db, inventory, soar
from ..agents import vm_agent
from ..agents.base import AgentFailed
from ..tools import tickets_api

OPEN_STATES = ("new", "triaged", "assigned", "in_remediation", "pending_verification", "reopened")


def _ver(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v)))


def _hist(f, state, note):
    h = db.loads(f.get("history"), []) or []
    h.append({"ts": db.now(), "state": state, "note": note})
    return h


def get(fid):
    f = db.one("SELECT * FROM findings WHERE id=?", (fid,))
    if f:
        for k in ("applicability", "exception", "history", "proposal"):
            f[k] = db.loads(f[k], f[k])
    return f


def set_state(fid, state, note, **fields):
    f = db.one("SELECT * FROM findings WHERE id=?", (fid,))
    db.update("findings", "id", fid, {"state": state, "history": _hist(f, state, note), **fields})
    db.audit(None, "vm", "finding_state", {"finding": fid, "state": state, "note": note})


def _ticket(fid, **patch):
    f = get(fid)
    if f and f["ticket_id"]:
        tickets_api().patch(f"/tickets/{f['ticket_id']}", json=patch)


# ---------------- job 1: asset sync ----------------

def asset_sync():
    known = set(inventory.hosts())
    seen = {r["host"] for r in db.query("SELECT DISTINCT host FROM events WHERE host IS NOT NULL")}
    shadow = sorted(seen - known)
    db.execute("INSERT OR REPLACE INTO kv (k, v) VALUES ('shadow_it', ?)", (json.dumps(shadow),))
    if shadow:
        db.audit(None, "vm", "shadow_it", {"hosts": shadow, "note": "unknown hosts queued for discovery scan"})
    return {"known": len(known), "shadow_it": shadow}


# ---------------- jobs 2-4: scan, enrich & score, dedupe & track ----------------

def scan(hosts=None):
    """Mock scanner: compare each host's package list with the catalogue."""
    cat = inventory.catalogue()
    raw = []
    for name, h in inventory.hosts().items():
        if hosts and name not in hosts:
            continue
        for pkg, ver in h["packages"].items():
            for v in cat.values():
                if v["product"] != pkg:
                    continue
                if v["fixed_version"] is None or _ver(ver) < _ver(v["fixed_version"]):
                    raw.append({"host": name, "cve": v["cve"], "port": v.get("port"), "package": pkg,
                                "installed_version": ver})
    return raw


def fingerprint(r):
    return "VF-" + hashlib.sha1(f"{r['host']}|{r['cve']}|{r['port']}".encode()).hexdigest()[:10]


def run_scan(hosts=None, reason="scheduled"):
    raw = scan(hosts)
    cat = inventory.catalogue()
    now = db.now()
    found, summary = set(), {"new": 0, "still_open": 0, "reopened": 0, "closed": 0}
    for r in raw:
        fid = fingerprint(r)
        found.add(fid)
        v, h = cat[r["cve"]], inventory.host(r["host"])
        s = scoring.score(v, h)
        cur = get(fid)
        if not cur:
            db.insert("findings", {**r, "id": fid, "state": "new", "cvss": v["cvss"], "epss": v["epss"],
                                   "kev": int(v["kev"]), "risk": s["risk"], "priority": s["priority"],
                                   "sla_due": now + s["sla_hours"] * 3600, "first_seen": now, "last_seen": now,
                                   "history": [{"ts": now, "state": "new", "note": f"first seen ({reason} scan)"}]})
            set_state(fid, "triaged", f"scored: {s['explain']}")
            summary["new"] += 1
            continue
        db.update("findings", "id", fid, {"last_seen": now, "installed_version": r["installed_version"]})
        if cur["state"] == "pending_verification":
            set_state(fid, "reopened", "verification rescan still finds the vulnerability (fix failed)")
            _ticket(fid, status="escalated", escalated=True, note="Fix failed verification rescan; escalated.")
            summary["reopened"] += 1
        elif cur["state"] == "closed":
            set_state(fid, "reopened", "vulnerability reappeared after it was closed")
            _ticket(fid, status="reopened", note="Finding reappeared.")
            summary["reopened"] += 1
        else:
            summary["still_open"] += 1
    scanned = set(hosts) if hosts else set(inventory.hosts())
    for f in db.query(f"SELECT id, state, host FROM findings WHERE state IN ({','.join('?' * len(OPEN_STATES))})",
                      OPEN_STATES):
        if f["host"] in scanned and f["id"] not in found:
            set_state(f["id"], "closed", "rescan no longer finds it (fix verified)")
            _ticket(f["id"], status="closed", note="Verified fixed by rescan.")
            summary["closed"] += 1
    return summary


# ---------------- job 5-6: VM agent and ticketing ----------------

def vm_agent_job():
    out = []
    cat = inventory.catalogue()
    for f in db.query("SELECT id FROM findings WHERE state='triaged' AND priority IN ('P1','P2','P3') "
                      "AND ticket_id IS NULL AND (proposal IS NULL OR proposal='')"):
        f = get(f["id"])
        h = inventory.host(f["host"])
        try:
            res, meta = vm_agent.run(f, cat[f["cve"]], h)
        except AgentFailed as e:
            db.audit(None, "vm-agent", "escalated", {"finding": f["id"], "reason": str(e)})
            continue
        db.update("findings", "id", f["id"], {"summary": res["summary"], "fix_plan": res["fix_plan"],
                                              "campaign": res["campaign"], "applicability": res["applicability"]})
        if res["propose_false_positive"]:
            db.update("findings", "id", f["id"], {"proposal": {"type": "false_positive",
                                                               "evidence": res["false_positive_evidence"],
                                                               "by": "vm-agent", "ts": db.now()}})
            db.audit(None, "vm-agent", "proposal", {"finding": f["id"], "type": "false_positive",
                                                    "evidence": res["false_positive_evidence"]})
        else:
            ticketing(f["id"], res["ticket_title"], res["ticket_body"])
        out.append({"finding": f["id"], "provider": meta["provider"], "fp": res["propose_false_positive"]})
    return out


def ticketing(fid, title=None, body=None):
    f = get(fid)
    h = inventory.host(f["host"])
    if f["ticket_id"]:
        _ticket(fid, priority=f["priority"], due=f["sla_due"], status="open", note="Re-assigned")
    else:
        t = tickets_api().post("/tickets", json={
            "finding_id": fid, "title": title or f"[{f['priority']}] {f['cve']} on {f['host']}",
            "assignee": h["owner"], "due": f["sla_due"], "priority": f["priority"],
            "body": body or (f.get("fix_plan") or "")}).json()
        db.update("findings", "id", fid, {"ticket_id": t["id"]})
    set_state(fid, "assigned", f"ticket assigned to {h['owner']}")


# ---------------- job 7: remediation through the approval gate ----------------

def remediation_tier(h):
    if h["role"] == "workstation" and h.get("maintenance_window"):
        return 1, "workstation patch in maintenance window"
    if h["criticality"] == "critical" or h.get("environment") == "production":
        return 3, "critical or production server"
    return 2, "non-critical server"


def plan_remediation(fid, case_id=None):
    f = get(fid)
    if soar_pending_for(fid):
        return None
    v = inventory.catalogue()[f["cve"]]
    h = inventory.host(f["host"])
    if v["fixed_version"]:
        tier, why = remediation_tier(h)
        step = {"step": "patch", "tool": "patch.apply",
                "params": {"host": f["host"], "package": f["package"], "version": v["fixed_version"]},
                "base_tier": tier, "tier_override": (tier, [why])}
    else:
        step = {"step": "compensating_control", "tool": "patch.control",
                "params": {"host": f["host"], "control": "block_port", "port": v.get("port")},
                "base_tier": 2, "tier_override": (2, ["compensating control"])}
    [aid] = soar.submit(case_id, [step], {}, playbook="vm_remediation", finding_id=fid, actor="vm-remediation")
    a = soar.get(aid)
    if a["status"] == "executed":
        on_action_done(a)
    else:
        db.audit(None, "vm", "awaiting_approval", {"finding": fid, "action": aid, "tier": a["tier"]})
    return aid


def soar_pending_for(fid):
    return db.one("SELECT id FROM actions WHERE finding_id=? AND status='pending_approval'", (fid,))


def remediation_job():
    out = []
    for f in db.query("SELECT id FROM findings WHERE state IN ('assigned','reopened') AND "
                      "(exception IS NULL OR exception='')"):
        if not soar_pending_for(f["id"]) and not _control_applied(f["id"]):
            out.append(plan_remediation(f["id"]))
    return [a for a in out if a]


def _control_applied(fid):
    return db.one("SELECT id FROM actions WHERE finding_id=? AND tool='patch.control' AND status='executed'", (fid,))


def on_action_done(a):
    fid = a["finding_id"]
    if a["status"] == "executed" and a["tool"] == "patch.apply":
        set_state(fid, "in_remediation", f"patch approved/applied (tier {a['tier']})")
        set_state(fid, "pending_verification", "remediation reported done; rescan queued")
        _ticket(fid, status="pending_verification", note=f"Patched to {a['params']['version']}; awaiting rescan.")
    elif a["status"] == "executed" and a["tool"] == "patch.control":
        set_state(fid, "in_remediation", "compensating control applied; risk exception required (no patch)")
        _ticket(fid, note="Compensating control applied (port blocked). Owner must file a risk exception.")
    elif a["status"] == "rejected":
        set_state(fid, "assigned", "remediation rejected by approver")
        _ticket(fid, note="Remediation rejected by approver.")


# ---------------- job 8: verify ----------------

def verify_job():
    hosts = sorted({r["host"] for r in db.query("SELECT host FROM findings WHERE state='pending_verification'")})
    return run_scan(hosts, reason="verification") if hosts else {}


# ---------------- job 9: SLA monitor ----------------

def sla_monitor():
    now, out = db.now(), []
    for f in db.query("SELECT * FROM findings WHERE state IN ('triaged','assigned','in_remediation',"
                      "'pending_verification','reopened')"):
        total = f["sla_due"] - f["first_seen"]
        frac = (now - f["first_seen"]) / total if total else 1
        if now > f["sla_due"] and not f["sla_breached"]:
            db.update("findings", "id", f["id"], {"sla_breached": 1, "sla_warned": 1})
            _ticket(f["id"], escalated=True, status="escalated", note="SLA breached: escalated to SOC lead.")
            db.audit(None, "vm", "sla_breach", {"finding": f["id"], "priority": f["priority"]})
            out.append((f["id"], "breach"))
        elif frac >= 0.75 and not f["sla_warned"]:
            db.update("findings", "id", f["id"], {"sla_warned": 1})
            _ticket(f["id"], note=f"SLA warning: {frac:.0%} of the SLA used.")
            db.audit(None, "vm", "sla_warning", {"finding": f["id"], "used": round(frac, 2)})
            out.append((f["id"], "warning"))
    return out


# ---------------- job 10: exceptions ----------------

def accept_risk(fid, reason, control, days, approvals):
    """approvals: list of {"user", "role"}; required roles depend on priority."""
    f = get(fid)
    if days > 90:
        raise ValueError("exception expiry must be at most 90 days")
    need = scoring.EXCEPTION_APPROVERS[f["priority"]]
    have = {a["role"] for a in approvals}
    if not need <= have:
        raise ValueError(f"{f['priority']} exception needs approval from {sorted(need)}")
    exc = {"reason": reason, "control": control, "expiry": db.now() + days * 86400, "approvals": approvals}
    set_state(fid, "risk_accepted", f"risk accepted for {days} days: {reason}", exception=exc)
    _ticket(fid, status="risk_accepted", note=f"Risk accepted until expiry ({days} days).")


def exception_expiry():
    out = []
    for f in db.query("SELECT id, exception FROM findings WHERE state='risk_accepted'"):
        exc = db.loads(f["exception"], {})
        if exc and db.now() > exc["expiry"]:
            set_state(f["id"], "reopened", "risk exception expired")
            db.update("findings", "id", f["id"], {"exception": None})
            ticketing(f["id"])
            out.append(f["id"])
    return out


def confirm_false_positive(fid, user, confirm=True):
    f = get(fid)
    if not f.get("proposal"):
        raise ValueError("no false-positive proposal on this finding")
    if confirm:
        set_state(fid, "false_positive", f"false positive confirmed by {user}: {f['proposal']['evidence']}",
                  proposal=None)
    else:
        db.update("findings", "id", fid, {"proposal": None})
        ticketing(fid)
        db.audit(None, user, "fp_rejected", {"finding": fid})


# ---------------- links to the SOC loop ----------------

def emergency_patch(fid, case_id):
    f = get(fid)
    set_state(fid, f["state"], f"exploit attempt seen in {case_id}: escalated to P1 emergency patch",
              priority="P1", sla_due=min(f["sla_due"], db.now() + 72 * 3600))
    if not f["ticket_id"]:
        ticketing(fid, title=f"[P1 EMERGENCY] {f['cve']} on {f['host']} - exploit attempt ({case_id})")
    else:
        _ticket(fid, priority="P1", note=f"Emergency: exploit attempt in {case_id}.")
        set_state(fid, "assigned", "emergency re-assignment")
    aid = plan_remediation(fid, case_id=case_id)
    db.audit(case_id, "vm", "emergency_patch", {"finding": fid, "action": aid})
    return aid


def escalate_from_incident(host, cve, case_id):
    f = db.one("SELECT id, priority FROM findings WHERE host=? AND cve=? AND state NOT IN ('closed','false_positive')",
               (host, cve))
    if f and f["priority"] != "P1":
        cur = get(f["id"])
        set_state(f["id"], cur["state"], f"root cause of {case_id}: escalated to P1", priority="P1",
                  sla_due=min(cur["sla_due"], db.now() + 72 * 3600))
        db.audit(case_id, "reporting", "root_cause_cve", {"finding": f["id"], "cve": cve})


def kev_update(cve):
    """New KEV entry: rescore, emergency rescan, and open a 30-day threat-hunt case."""
    inventory.add_kev(cve)
    v = inventory.catalogue()[cve]
    for f in db.query("SELECT id, host FROM findings WHERE cve=?", (cve,)):
        s = scoring.score(v, inventory.host(f["host"]))
        cur = get(f["id"])
        set_state(f["id"], cur["state"], f"CVE added to KEV; rescored: {s['explain']}", kev=1, risk=s["risk"],
                  priority=s["priority"])
    scan_summary = run_scan(reason="emergency KEV")
    since = db.now() - 30 * 86400
    hits = db.query("SELECT id, ts, host, action FROM events WHERE ts>=? AND (raw LIKE ? OR raw LIKE ?) LIMIT 100",
                    (since, f"%{cve}%", f"%{v['product']}%"))
    case_id = "HUNT-" + db.new_id("x")[2:].upper()
    db.insert("cases", {
        "id": case_id, "created": db.now(), "updated": db.now(), "kind": "hunt",
        "title": f"Threat hunt: exploitation of {cve} ({v['product']}) in the last 30 days",
        "status": "closed" if not hits else "awaiting_approval", "severity": "high",
        "summary": f"Searched 30 days of logs for {cve}/{v['product']}: {len(hits)} matching events.",
        "report": {"hunt": {"cve": cve, "hits": hits, "rescan": scan_summary}}})
    db.audit(case_id, "vm", "threat_hunt", {"cve": cve, "hits": len(hits)})
    return case_id


# ---------------- job 11: weekly posture report ----------------

def weekly_report():
    from ..agents import base
    rows = db.query("SELECT priority, state, sla_breached FROM findings")
    open_rows = [r for r in rows if r["state"] not in ("closed", "false_positive")]
    stats = {"open_by_priority": {p: sum(1 for r in open_rows if r["priority"] == p) for p in ("P1", "P2", "P3", "P4")},
             "total": len(rows), "closed": sum(1 for r in rows if r["state"] == "closed"),
             "sla_breaches": sum(r["sla_breached"] or 0 for r in rows),
             "top_risks": db.query("SELECT host, cve, risk, priority, state FROM findings WHERE state NOT IN "
                                   "('closed','false_positive') ORDER BY risk DESC LIMIT 5")}
    stats["sla_compliance"] = round(1 - stats["sla_breaches"] / max(1, len(rows)), 3)

    def validate(o):
        base.need(o, "summary", str)
        return o
    out, meta = base.run("reporting", None,
                         'ROLE: write the weekly vulnerability posture summary for the SOC lead. Return JSON '
                         '{"summary": "markdown, 1-2 short paragraphs plus a bullet list of the top risks"}',
                         json.dumps(stats), validate,
                         lambda: {"summary": f"Open findings by priority: {stats['open_by_priority']}. "
                                             f"SLA compliance {stats['sla_compliance']:.0%}."})
    report = {"ts": db.now(), "stats": stats, "summary": out["summary"], "provider": meta["provider"]}
    db.execute("INSERT OR REPLACE INTO kv (k, v) VALUES ('vm_weekly_report', ?)", (json.dumps(report),))
    return report


def run_cycle():
    """Jobs 1-10 in order (on demand; APScheduler runs them on their own triggers)."""
    return {"asset_sync": asset_sync(), "scan": run_scan(), "vm_agent": vm_agent_job(),
            "remediation": remediation_job(), "verify": verify_job(), "sla": sla_monitor(),
            "exceptions": exception_expiry()}
