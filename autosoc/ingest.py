"""Live log ingestion: POST /ingest (ECS JSON) and POST /ingest/syslog (raw lines).

Every event takes the same path as a scenario replay: siem.store_event -> RuleEngine.process ->
siem.store_alert -> orchestrator.process_alert. One long-lived RuleEngine keeps threshold windows
(brute force) across requests. Alerts go to a background worker, so the HTTP response never waits
for the agents.

The worker lets each alert settle before the agents see it: it waits until the activity behind the
alert (same host + source IP, or host + user) has been quiet for SETTLE_QUIET_S seconds, at most
SETTLE_MAX_S. A scenario replay sees the whole window at once; a live feed has to wait for it, or
the agents would judge a brute force before the successful login that follows it arrives.
"""
import datetime as dt
import os
import re
import threading
import time

from fastapi import APIRouter, Body, HTTPException, Request
from fastapi.concurrency import run_in_threadpool

from . import db, siem, telemetry
from .agents import orchestrator

RUN_ID = "live"
SETTLE_QUIET_S = float(os.getenv("INGEST_SETTLE_QUIET_S", "10"))
SETTLE_MAX_S = float(os.getenv("INGEST_SETTLE_MAX_S", "120"))

router = APIRouter(prefix="/ingest", tags=["ingest"])

_engine = None
_engine_lock = threading.Lock()      # RuleEngine windows are not thread-safe; requests run in a pool
_work_lock = threading.Lock()        # one alert at a time through the agents (dedupe needs order)
_pending = []                        # [(alert, keys, queued_at)]
_last_seen = {}                      # activity key -> wall time of the last event
_stats = {"events": 0, "alerts": 0, "processed": 0, "errors": 0, "in_flight": 0, "started": time.time()}
_worker = None


def engine():
    global _engine
    if _engine is None:
        _engine = siem.RuleEngine()
    return _engine


def reset():
    """Forget threshold windows and queued alerts (tests, or after wiping the database)."""
    global _engine
    with _engine_lock:
        _engine = None
        _pending.clear()
        _last_seen.clear()


# ---------------- parsing ----------------

def _flatten(d, prefix=""):
    out = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, key + "."))
        else:
            out[key] = v
    return out


def _epoch(v):
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v) / 1000 if v > 1e12 else float(v)  # epoch ms from some shippers
    try:
        return float(v)
    except ValueError:
        pass
    try:
        t = dt.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return (t if t.tzinfo else t.astimezone()).timestamp()
    except ValueError:
        return None


def prepare(raw):
    """Nested or flat ECS (or the scenario short aliases) -> a flat event with an id and timestamp."""
    if not isinstance(raw, dict):
        raise ValueError("each event must be a JSON object")
    ev = telemetry.normalise(_flatten(raw))
    now = db.now()
    ev["@timestamp"] = _epoch(ev.get("@timestamp")) or now
    ev["event.ingested"] = now
    ev["_id"] = db.new_id("evt")
    return ev


_SYSLOG = re.compile(r"^(?:<\d+>)?(?P<ts>[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d) (?P<host>\S+) "
                     r"(?P<prog>[\w./-]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$")
_SSHD = re.compile(r"^(?P<result>Failed|Accepted) (?P<method>password|publickey|keyboard-interactive/pam) for "
                   r"(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)(?: port (?P<port>\d+))?")


def parse_syslog(line):
    """One BSD-syslog line -> ECS fields. sshd logins become ssh_login_failed / ssh_login_success."""
    line = line.rstrip("\r\n")
    m = _SYSLOG.match(line)
    if not m:
        return {"event.module": "syslog", "event.action": "syslog_message", "message": line,
                "event.original": line}
    ev = {"event.module": "syslog", "event.action": "syslog_message", "host.name": m["host"],
          "process.name": m["prog"], "message": m["msg"], "event.original": line}
    if m["pid"]:
        ev["process.pid"] = int(m["pid"])
    try:
        t = dt.datetime.strptime(f"{dt.date.today().year} {m['ts']}", "%Y %b %d %H:%M:%S")
        if t > dt.datetime.now() + dt.timedelta(days=1):  # December log read in January
            t = t.replace(year=t.year - 1)
        ev["@timestamp"] = t.timestamp()
    except ValueError:
        pass
    s = _SSHD.match(m["msg"]) if m["prog"] == "sshd" else None
    if s:
        ok = s["result"] == "Accepted"
        ev.update({"event.module": "auditd", "event.dataset": "sshd",
                   "event.action": "ssh_login_success" if ok else "ssh_login_failed",
                   "event.outcome": "success" if ok else "failure", "user.name": s["user"],
                   "source.ip": s["ip"], "auth.method": s["method"]})
        if s["port"]:
            ev["source.port"] = int(s["port"])
        if s["invalid"]:
            ev["user.invalid"] = True
    return ev


# ---------------- pipeline ----------------

def _keys(ev):
    h = ev.get("host.name")
    return {("ip", h, ev.get("source.ip")), ("user", h, ev.get("user.name")), ("host", h)}


def _alert_key(a):
    if a.get("src_ip"):
        return ("ip", a["host"], a["src_ip"])
    if a.get("user"):
        return ("user", a["host"], a["user"])
    return ("host", a["host"])


def ingest(events):
    """Store, detect and queue alerts. Returns the per-event summary sent back to the shipper."""
    out = []
    wall = time.time()
    with _engine_lock:
        for ev in events:
            siem.store_event(ev, RUN_ID)
            for k in _keys(ev):
                _last_seen[k] = wall
            alerts = engine().process(ev)
            for a in alerts:
                siem.store_alert(a, RUN_ID)
                _pending.append((a, _alert_key(a), wall))
            _stats["events"] += 1
            _stats["alerts"] += len(alerts)
            out.append({"id": ev["_id"], "alerts": [a["id"] for a in alerts]})
    _ensure_worker()
    return out


def _due(now=None):
    now = now or time.time()
    with _engine_lock:
        due = [p for p in _pending if now - _last_seen.get(p[1], 0) >= SETTLE_QUIET_S
               or now - p[2] >= SETTLE_MAX_S]
        for p in due:
            _pending.remove(p)
    return due


def _process(items):
    _stats["in_flight"] = len(items)
    for alert, _, _ in items:
        try:
            orchestrator.process_alert(alert, RUN_ID, "live")
            _stats["processed"] += 1
        except Exception as e:  # one bad alert must not stop the feed
            _stats["errors"] += 1
            db.audit(None, "ingest", "error", {"alert": alert["id"], "error": repr(e)})
        _stats["in_flight"] -= 1


def flush():
    """Send every queued alert to the agents now, ignoring the settle time (tests, shutdown)."""
    with _work_lock:
        _process(_due(now=float("inf")))


def _loop():
    while True:
        time.sleep(1)
        with _work_lock:
            _process(_due())


def _ensure_worker():
    global _worker
    if _worker is None or not _worker.is_alive():
        _worker = threading.Thread(target=_loop, name="ingest-worker", daemon=True)
        _worker.start()


# ---------------- HTTP ----------------

@router.post("")
def ingest_json(payload: dict | list = Body(...)):
    """One ECS event or a JSON array of events (nested or dotted keys, or the scenario aliases)."""
    items = payload if isinstance(payload, list) else [payload]
    try:
        events = [prepare(e) for e in items]
    except ValueError as e:
        raise HTTPException(422, str(e))
    res = ingest(events)
    return {"accepted": len(res), "alerts": [a for r in res for a in r["alerts"]], "events": res}


@router.post("/syslog")
async def ingest_syslog(request: Request):
    """Raw syslog text, one line per event (text/plain body)."""
    body = (await request.body()).decode("utf-8", "replace")
    events = [prepare(parse_syslog(line)) for line in body.splitlines() if line.strip()]
    res = await run_in_threadpool(ingest, events)
    return {"accepted": len(res), "alerts": [a for r in res for a in r["alerts"]], "events": res}


@router.get("/status")
def status():
    cases = db.query("SELECT id, status, verdict, title FROM cases WHERE run_id=? ORDER BY created", (RUN_ID,))
    return {**_stats, "pending_alerts": len(_pending), "settle_quiet_s": SETTLE_QUIET_S, "cases": cases}
