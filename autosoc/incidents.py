"""Correlate cases into incidents and score severity.

A case is one alert group the agents worked. An incident links cases that share a host, user or
indicator inside a time window, so a multi-stage attack (phishing -> execution -> credential access)
reads as one story instead of three disconnected cases.

Severity score (0-100) combines, per the client's "severity of situation" ask:
  stage reached (how deep the kill chain got) x asset importance x user privilege
  + threat-intel confirmation + the agents' own confidence.
It maps to low / medium / high / critical, which drives the response posture.
"""
from . import db, inventory

# ATT&CK tactic -> kill-chain depth (0..1). Later stages are worse.
TACTIC_STAGE = {
    "T1566": 0.3,            # phishing / initial access
    "T1190": 0.4,            # exploit public-facing
    "T1110": 0.35,           # brute force
    "T1059": 0.5, "T1059.001": 0.5, "T1218": 0.5, "T1218.005": 0.5, "T1197": 0.45,  # execution
    "T1078": 0.6,            # valid accounts
    "T1053": 0.65, "T1053.005": 0.65, "T1136": 0.65, "T1136.001": 0.65,  # persistence
    "T1069": 0.55, "T1069.001": 0.55,  # discovery
    "T1003": 0.85, "T1003.001": 0.85,  # credential access
    "T1021": 0.8, "T1021.002": 0.8,    # lateral movement
    "T1048": 0.9,            # exfiltration
}
ASSET_W = {"critical": 1.0, "high": 0.8, "normal": 0.6, "low": 0.4}
PRIV_W = {"exec": 1.0, "admin": 1.0, "service": 0.8, "user": 0.6}
WINDOW_S = 3600


def _stage(mitre_list):
    return max([TACTIC_STAGE.get(m, 0.4) for m in (mitre_list or [])], default=0.4)


def severity_score(cases):
    """Return (score 0-100, band, rationale) for a set of cases forming one incident."""
    mitre = sorted({m for c in cases for m in db.loads(c["mitre"], [])})
    stage = _stage(mitre)
    host = next((c["host"] for c in cases if c["host"]), None)
    user = next((c["user"] for c in cases if c["user"]), None)
    h = inventory.host(host or "") or {}
    u = inventory.user(user or "") or {}
    asset = ASSET_W.get(h.get("criticality"), 0.6)
    priv = PRIV_W.get(u.get("role"), 0.6)
    confirmed = any(c["verdict"] == "malicious" for c in cases)
    confidence = max([c["confidence"] or 0 for c in cases], default=0.5)
    exposure_bump = 0.1 if h.get("exposure") == "internet-facing" else 0.0
    multi = 0.1 if len({m.split(".")[0] for m in mitre}) >= 2 else 0.0  # multiple tactics = a chain

    base = stage * (0.6 + 0.4 * asset) * (0.7 + 0.3 * priv)
    score = 100 * min(1.0, base + (0.15 if confirmed else 0.0) + 0.1 * confidence + exposure_bump + multi)
    score = round(score, 1)
    band = ("critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low")
    rationale = (f"stage {stage:.2f} (deepest tactic), asset {h.get('criticality', '?')} , "
                 f"user {u.get('role', '?')}, "
                 f"{'intel-confirmed, ' if confirmed else ''}"
                 f"{'multi-stage chain, ' if multi else ''}confidence {confidence:.0%}")
    return score, band, rationale, mitre, host, user


def _open_incident_for(host, user):
    since = db.now() - WINDOW_S
    for inc in db.query("SELECT * FROM incidents WHERE status='open' AND updated>=? ORDER BY updated DESC",
                        (since,)):
        if (host and inc["host"] == host) or (user and inc["user"] == user):
            return inc
    return None


def correlate(case):
    """Attach a case to an existing incident (same host/user, recent) or open a new one. Rescore."""
    inc = _open_incident_for(case["host"], case["user"])
    if inc:
        case_ids = sorted(set(db.loads(inc["case_ids"], []) + [case["id"]]))
        incident_id = inc["id"]
    else:
        incident_id = "INC-" + db.new_id("x")[2:].upper()
        case_ids = [case["id"]]

    cases = [db.one("SELECT * FROM cases WHERE id=?", (cid,)) for cid in case_ids]
    cases = [c for c in cases if c]
    score, band, rationale, mitre, host, user = severity_score(cases)
    stages = sorted({m for c in cases for m in db.loads(c["mitre"], [])})
    title = f"{band.upper()} incident on {host or user or 'unknown'}: " + ", ".join(stages[:4])
    row = {"id": incident_id, "updated": db.now(), "title": title, "status": "open", "severity": band,
           "severity_score": score, "host": host, "user": user, "mitre": mitre, "case_ids": case_ids,
           "alert_ids": [], "stages": stages, "rationale": rationale}
    if not inc:
        row["created"] = db.now()
    db.insert("incidents", {**(inc or {}), **row})
    db.audit(case["id"], "correlation", "incident",
             {"incident": incident_id, "severity": band, "score": score, "cases": case_ids})
    return get(incident_id)


def get(incident_id):
    inc = db.one("SELECT * FROM incidents WHERE id=?", (incident_id,))
    if inc:
        for k in ("case_ids", "alert_ids", "mitre", "stages"):
            inc[k] = db.loads(inc[k], [])
    return inc


def list_open():
    rows = db.query("SELECT * FROM incidents ORDER BY severity_score DESC, updated DESC")
    for r in rows:
        for k in ("case_ids", "alert_ids", "mitre", "stages"):
            r[k] = db.loads(r[k], [])
    return rows
