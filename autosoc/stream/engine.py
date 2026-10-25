"""The live SOC loop: one continuous stream -> detect -> agents -> incident -> scoreboard.

Per tick it emits benign events at a target rate and, every INTERVAL seconds, injects one attack
(synthetic or a real OTRF capture). Every event is stored (and categorised there), run through both
detectors (Sigma rules + behaviour baselines), and any alert is queued. Alerts settle briefly, then
the agents work them into cases; each case is correlated into an incident and scored for severity.
Injected attacks are matched against the cases they produced, so the scoreboard can show what was
caught, missed, and how fast.
"""
import threading
import time

from .. import db, incidents, siem
from ..agents import orchestrator
from ..detect.baseline import Baselines
from . import simulator

RUN_ID = "stream"

DEFAULT_RATE = 5.0        # benign events per second
DEFAULT_INTERVAL = 30.0   # seconds between attack injections
SETTLE_QUIET_S = 6.0
SETTLE_MAX_S = 45.0


class StreamEngine:
    def __init__(self, rate=DEFAULT_RATE, interval=DEFAULT_INTERVAL, attack_kind=None):
        self.rate, self.interval, self.attack_kind = rate, interval, attack_kind
        self.rules = siem.RuleEngine()
        self.baselines = Baselines()
        self.baselines.learn_from_db()
        self._pending = []          # [(alert, key, queued_at)]
        self._last_seen = {}
        self._stop = threading.Event()
        self._thread = None
        self.stats = {"events": 0, "benign": 0, "attacks": 0, "alerts": 0, "cases": 0, "started": time.time()}

    # ---- detection on one event ----
    def _detect(self, ev):
        alerts = self.rules.process(ev)
        alerts += self.baselines.ask(ev)
        self.baselines.observe(ev)
        return alerts

    def _emit(self, ev, injection_id=None):
        ev["_id"] = db.new_id("evt")
        ev["@timestamp"] = db.now()
        siem.store_event(ev, RUN_ID)
        self.stats["events"] += 1
        wall = time.time()
        for k in ({("ip", ev.get("host.name"), ev.get("source.ip")),
                   ("user", ev.get("host.name"), ev.get("user.name")),
                   ("host", ev.get("host.name"))}):
            self._last_seen[k] = wall
        for a in self._detect(ev):
            siem.store_alert(a, RUN_ID)
            self.stats["alerts"] += 1
            key = ("ip", a["host"], a["src_ip"]) if a.get("src_ip") else \
                  ("user", a["host"], a["user"]) if a.get("user") else ("host", a["host"])
            self._pending.append((a, key, wall))
        return ev["_id"]

    # ---- attack injection ----
    def inject_attack(self, kind=None, technique=None):
        if technique:
            evs, meta = simulator.make_specific(technique)
        else:
            evs, meta = simulator.make_attack(kind or self.attack_kind)
        ids = [self._emit(dict(e)) for e in evs]
        inj = simulator.record_injection(meta, ids, db.now())
        self.stats["attacks"] += 1
        db.audit(None, "stream", "attack_injected",
                 {"injection": inj, "label": meta["label"], "origin": meta["origin"], "mitre": meta.get("mitre")})
        return inj, meta

    # ---- alert settling + agents ----
    def _due(self, now):
        due = [p for p in self._pending
               if now - self._last_seen.get(p[1], 0) >= SETTLE_QUIET_S or now - p[2] >= SETTLE_MAX_S]
        for p in due:
            self._pending.remove(p)
        return due

    def _work(self, now=None):
        for alert, _, _ in self._due(now or time.time()):
            try:
                case_id, merged = orchestrator.process_alert(alert, RUN_ID, "stream")
                if not merged:
                    self.stats["cases"] += 1
                case = db.one("SELECT * FROM cases WHERE id=?", (case_id,))
                if case and case["verdict"] not in ("false_positive", "benign"):
                    incidents.correlate(case)
                self._match_ground_truth(alert, case_id)
            except Exception as e:
                db.audit(None, "stream", "error", {"alert": alert["id"], "error": repr(e)})

    def _match_ground_truth(self, alert, case_id):
        case = db.one("SELECT * FROM cases WHERE id=?", (case_id,))
        detected = case and case["verdict"] not in ("false_positive", "benign")
        alert_events = set(db.loads(alert.get("event_ids"), []) if isinstance(alert.get("event_ids"), str)
                           else alert.get("event_ids", []))
        for inj in db.query("SELECT * FROM injections WHERE detected=0"):
            inj_events = set(db.loads(inj["event_ids"], []))
            same = alert_events & inj_events
            if same or (inj["host"] and inj["host"] == alert.get("host") and inj["indicator"]
                        and inj["indicator"] == alert.get("src_ip")):
                if detected:
                    db.update("injections", "id", inj["id"],
                              {"detected": 1, "matched_case": case_id,
                               "detect_latency": round(db.now() - inj["ts"], 1)})
                break

    # ---- loop control ----
    def warmup(self, n=200):
        """Seed normal history and learn baselines before detection starts, so legitimate logins to
        known servers are not flagged as 'first time'. Warm-up events are stored but not detected on."""
        for _ in range(n):
            ev = simulator._benign_event()
            ev["_id"] = db.new_id("evt")
            ev["@timestamp"] = db.now()
            siem.store_event(ev, RUN_ID)
            self.baselines.observe(ev)
            self.stats["events"] += 1
            self.stats["benign"] += 1
        return self

    def run_for(self, seconds, flush=True, warmup=True, first_attack_after=None):
        """Run the stream synchronously for a fixed time (demo/tests)."""
        if warmup:
            self.warmup()
        end = time.time() + seconds
        next_attack = time.time() + (self.interval if first_attack_after is None else first_attack_after)
        gap = 1.0 / self.rate if self.rate > 0 else 1.0
        while time.time() < end and not self._stop.is_set():
            self._emit(simulator._benign_event())
            self.stats["benign"] += 1
            if time.time() >= next_attack:
                self.inject_attack()
                next_attack = time.time() + self.interval
            self._work()
            time.sleep(gap)
        if flush:
            self._work(now=float("inf"))
        return self.stats

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="stream-engine", daemon=True)
        self._thread.start()

    def _loop(self):
        next_attack = time.time() + self.interval
        gap = 1.0 / self.rate if self.rate > 0 else 1.0
        while not self._stop.is_set():
            self._emit(simulator._benign_event())
            self.stats["benign"] += 1
            if time.time() >= next_attack:
                self.inject_attack()
                next_attack = time.time() + self.interval
            self._work()
            time.sleep(gap)

    def stop(self):
        self._stop.set()


def scoreboard():
    injs = db.query("SELECT * FROM injections ORDER BY ts")
    total = len(injs)
    detected = [i for i in injs if i["detected"]]
    by_origin = {}
    for i in injs:
        o = by_origin.setdefault(i["origin"], {"total": 0, "detected": 0})
        o["total"] += 1
        o["detected"] += 1 if i["detected"] else 0
    lat = [i["detect_latency"] for i in detected if i["detect_latency"] is not None]
    return {
        "injected": total, "detected": len(detected),
        "detection_rate": round(len(detected) / total, 3) if total else None,
        "by_origin": by_origin,
        "mean_detect_latency_s": round(sum(lat) / len(lat), 1) if lat else None,
        "missed": [{"label": i["label"], "mitre": i["mitre"], "origin": i["origin"]}
                   for i in injs if not i["detected"]],
    }
