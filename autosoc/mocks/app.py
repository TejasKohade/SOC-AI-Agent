"""Mock security tools behind realistic REST APIs.

Each endpoint stands in for a real product (threat intel, EDR, firewall, IdP, mail gateway,
ticketing, patching) so a mock can later be swapped for the real API without touching agents.
Every state-changing call is logged in `mock_state` and can be undone.
"""
import json
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .. import config, db, ingest, inventory

app = FastAPI(title="AutoSOC mock security tools")
app.include_router(ingest.router)  # live log feed: POST /ingest, /ingest/syslog


@app.on_event("startup")
def _startup():
    db.conn()


def _record(tool, op, target, params):
    rid = db.new_id("st")
    db.insert("mock_state", {"id": rid, "tool": tool, "op": op, "target": target,
                             "params": params, "ts": db.now(), "active": 1})
    return rid


def _active(tool, op, target):
    return db.one("SELECT * FROM mock_state WHERE tool=? AND op=? AND target=? AND active=1",
                  (tool, op, target))


def _deactivate(tool, op, target):
    db.execute("UPDATE mock_state SET active=0, undone_ts=? WHERE tool=? AND op=? AND target=? AND active=1",
               (db.now(), tool, op, target))


# ---------------- threat intelligence (MISP / VirusTotal / AbuseIPDB) ----------------

_IOCS = {i["value"].lower(): i for i in json.loads((config.INTEL_DIR / "iocs.json").read_text())["indicators"]}


@app.get("/intel/reputation")
def reputation(indicator: str):
    hit = _IOCS.get(indicator.lower())
    if hit:
        return {"indicator": indicator, **{k: hit[k] for k in ("type", "score", "verdict", "tags", "source")}}
    return {"indicator": indicator, "type": "unknown", "score": None, "verdict": "unknown", "tags": [], "source": None}


# ---------------- EDR ----------------

class HostReq(BaseModel):
    host: str
    reason: str = ""


class ProcReq(BaseModel):
    host: str
    process: str
    pid: int | None = None


class TaskReq(BaseModel):
    host: str
    task: str


@app.post("/edr/isolate")
def edr_isolate(r: HostReq):
    if not inventory.host(r.host):
        raise HTTPException(404, f"unknown host {r.host}")
    if _active("edr", "isolate", r.host):
        return {"ok": True, "already": True}
    return {"ok": True, "state_id": _record("edr", "isolate", r.host, r.model_dump())}


@app.post("/edr/unisolate")
def edr_unisolate(r: HostReq):
    _deactivate("edr", "isolate", r.host)
    return {"ok": True}


@app.post("/edr/kill_process")
def edr_kill(r: ProcReq):
    return {"ok": True, "state_id": _record("edr", "kill_process", r.host, r.model_dump())}


@app.post("/edr/remove_persistence")
def edr_remove_persistence(r: TaskReq):
    return {"ok": True, "state_id": _record("edr", "remove_persistence", r.host, r.model_dump())}


@app.post("/edr/restore_persistence")
def edr_restore_persistence(r: TaskReq):
    _deactivate("edr", "remove_persistence", r.host)
    return {"ok": True}


@app.get("/edr/hosts/{host}")
def edr_host(host: str):
    h = inventory.host(host)
    if not h:
        raise HTTPException(404, "unknown host")
    return {"host": host, "isolated": bool(_active("edr", "isolate", host)), "os": h["os"],
            "processes_killed": [db.loads(r["params"]) for r in db.query(
                "SELECT params FROM mock_state WHERE tool='edr' AND op='kill_process' AND target=?", (host,))]}


# ---------------- firewall ----------------

class BlockReq(BaseModel):
    indicator: str
    kind: str = "ip"  # ip | domain | port
    duration_h: int = 24
    host: str | None = None


@app.post("/firewall/block")
def fw_block(r: BlockReq):
    target = f"{r.host}:{r.indicator}" if r.kind == "port" else r.indicator
    if _active("firewall", "block", target):
        return {"ok": True, "already": True}
    return {"ok": True, "state_id": _record("firewall", "block", target,
                                             {**r.model_dump(), "expires": db.now() + r.duration_h * 3600})}


@app.post("/firewall/unblock")
def fw_unblock(r: BlockReq):
    target = f"{r.host}:{r.indicator}" if r.kind == "port" else r.indicator
    _deactivate("firewall", "block", target)
    return {"ok": True}


@app.get("/firewall/blocked")
def fw_blocked():
    return [dict(r, params=db.loads(r["params"])) for r in
            db.query("SELECT * FROM mock_state WHERE tool='firewall' AND op='block' AND active=1")]


# ---------------- identity provider ----------------

class UserReq(BaseModel):
    user: str
    reason: str = ""


@app.post("/idp/disable")
def idp_disable(r: UserReq):
    return {"ok": True, "state_id": _record("idp", "disable", r.user, r.model_dump())}


@app.post("/idp/enable")
def idp_enable(r: UserReq):
    _deactivate("idp", "disable", r.user)
    return {"ok": True}


@app.post("/idp/revoke_sessions")
def idp_revoke(r: UserReq):
    return {"ok": True, "state_id": _record("idp", "revoke_sessions", r.user, r.model_dump())}


@app.post("/idp/force_password_reset")
def idp_reset(r: UserReq):
    return {"ok": True, "state_id": _record("idp", "force_password_reset", r.user, r.model_dump())}


@app.get("/idp/users/{user}")
def idp_user(user: str):
    return {"user": user, "known": inventory.user(user) is not None,
            "disabled": bool(_active("idp", "disable", user)),
            "sessions_revoked": bool(_active("idp", "revoke_sessions", user))}


@app.get("/idp/signins/{user}")
def idp_signins(user: str):
    rows = db.query("SELECT id, ts, host, src_ip, action FROM events WHERE user=? AND action LIKE '%login%' "
                    "ORDER BY ts DESC LIMIT 50", (user,))
    return {"user": user, "signins": rows}


# ---------------- email gateway ----------------

class MailReq(BaseModel):
    message_id: str


@app.post("/email/quarantine")
def mail_quarantine(r: MailReq):
    if _active("email", "quarantine", r.message_id):
        return {"ok": True, "already": True}
    return {"ok": True, "state_id": _record("email", "quarantine", r.message_id, r.model_dump())}


@app.post("/email/release")
def mail_release(r: MailReq):
    _deactivate("email", "quarantine", r.message_id)
    return {"ok": True}


@app.get("/email/search")
def mail_search(url: str = "", sender: str = ""):
    rows = db.query("SELECT id, raw FROM events WHERE source='email'")
    out = []
    for r in rows:
        e = db.loads(r["raw"], {})
        if (url and url in (e.get("url.full") or "")) or (sender and sender == e.get("email.from")):
            out.append({"event_id": r["id"], "message_id": e.get("email.message_id"), "to": e.get("email.to")})
    return out


# ---------------- ticketing (Jira / ServiceNow) ----------------

class TicketReq(BaseModel):
    finding_id: str | None = None
    title: str
    assignee: str
    due: float | None = None
    priority: str = "P3"
    body: str = ""


class TicketPatch(BaseModel):
    status: str | None = None
    note: str | None = None
    escalated: bool | None = None
    assignee: str | None = None
    due: float | None = None
    priority: str | None = None


@app.post("/tickets")
def ticket_create(r: TicketReq):
    tid = f"TKT-{int(time.time() * 1000) % 10_000_000:07d}"
    while db.one("SELECT id FROM tickets WHERE id=?", (tid,)):
        tid = db.new_id("TKT")
    db.insert("tickets", {**r.model_dump(), "id": tid, "status": "open", "created": db.now(),
                          "updated": db.now(), "notes": []})
    return db.one("SELECT * FROM tickets WHERE id=?", (tid,))


@app.patch("/tickets/{tid}")
def ticket_patch(tid: str, r: TicketPatch):
    t = db.one("SELECT * FROM tickets WHERE id=?", (tid,))
    if not t:
        raise HTTPException(404, "no such ticket")
    fields = {k: v for k, v in r.model_dump().items() if v is not None and k != "note"}
    if "escalated" in fields:
        fields["escalated"] = int(fields["escalated"])
    notes = db.loads(t["notes"], [])
    if r.note:
        notes.append({"ts": db.now(), "note": r.note})
    db.update("tickets", "id", tid, {**fields, "notes": notes, "updated": db.now()})
    return db.one("SELECT * FROM tickets WHERE id=?", (tid,))


@app.get("/tickets")
def ticket_list():
    return db.query("SELECT * FROM tickets ORDER BY created DESC")


# ---------------- patching (WSUS / Ansible / Intune) ----------------

class PatchReq(BaseModel):
    host: str
    package: str
    version: str | None = None


class ControlReq(BaseModel):
    host: str
    control: str  # block_port | disable_service | waf_rule
    port: int | None = None
    service: str | None = None


@app.post("/patch/apply")
def patch_apply(r: PatchReq):
    h = inventory.host(r.host)
    if not h or r.package not in h["packages"]:
        raise HTTPException(404, "host or package not found")
    previous = h["packages"][r.package]
    # A host can be flagged to fail patching silently: the job reports success but the
    # version does not change, which the verification rescan must catch.
    if r.package not in h.get("patch_fails", []):
        h["packages"][r.package] = r.version
        inventory.save_host(h)
    sid = _record("patch", "apply", f"{r.host}:{r.package}", {**r.model_dump(), "previous": previous})
    return {"ok": True, "state_id": sid, "previous": previous, "reported_version": r.version}


@app.post("/patch/rollback")
def patch_rollback(r: PatchReq):
    st = db.one("SELECT * FROM mock_state WHERE tool='patch' AND op='apply' AND target=? AND active=1 "
                "ORDER BY ts DESC", (f"{r.host}:{r.package}",))
    if not st:
        raise HTTPException(404, "nothing to roll back")
    h = inventory.host(r.host)
    h["packages"][r.package] = db.loads(st["params"])["previous"]
    inventory.save_host(h)
    db.update("mock_state", "id", st["id"], {"active": 0, "undone_ts": db.now()})
    return {"ok": True, "version": h["packages"][r.package]}


@app.post("/patch/control")
def patch_control(r: ControlReq):
    return {"ok": True, "state_id": _record("patch", "control", f"{r.host}:{r.control}:{r.port or r.service}",
                                             r.model_dump())}


@app.post("/patch/control/remove")
def patch_control_remove(r: ControlReq):
    _deactivate("patch", "control", f"{r.host}:{r.control}:{r.port or r.service}")
    return {"ok": True}


@app.get("/state")
def state(active_only: bool = True):
    sql = "SELECT * FROM mock_state" + (" WHERE active=1" if active_only else "") + " ORDER BY ts DESC"
    return [dict(r, params=db.loads(r["params"])) for r in db.query(sql)]


@app.get("/health")
def health():
    return {"ok": True}
