"""Scenario replay: generator -> asyncio queue -> SIEM rule engine -> alert queue -> agent service.
VM scenarios are small step scripts over the vulnerability-management jobs. Every scenario carries
its expected outcome, so each one is also a test case."""
import asyncio
import json
import time
from pathlib import Path

import yaml

from . import config, db, siem, soar, telemetry
from .agents import orchestrator
from .telemetry import _parse_dur
from .vm import lifecycle

ANALYST = ("ana", "analyst")
SOC_LEAD = ("lee", "soc_lead")


def list_scenarios(kind=None):
    out = []
    for p in sorted(config.SCENARIO_DIR.glob("*/*.yml")):
        s = yaml.safe_load(p.read_text())
        k = "vm" if p.parent.name == "vm" else "soc"
        if kind in (None, k):
            out.append({"path": str(p), "id": s["id"], "kind": k, "mitre": s.get("mitre"),
                        "description": s.get("description", "")})
    return out


def find_scenario(sid):
    for s in list_scenarios():
        if s["id"] == sid or Path(s["path"]).stem == sid:
            return s["path"]
    raise KeyError(sid)


# ---------------- SOC ----------------

async def _replay(events, run_id, scenario_id, timings):
    q_events, q_alerts = asyncio.Queue(), asyncio.Queue()
    engine = siem.RuleEngine()

    async def producer():
        for e in events:
            await q_events.put(e)
        await q_events.put(None)

    async def detector():
        while (e := await q_events.get()) is not None:
            siem.store_event(e, run_id)
            for a in engine.process(e):
                siem.store_alert(a, run_id)
                timings.setdefault("first_alert", time.time())
                await q_alerts.put(a)
        await q_alerts.put(None)

    # Replay compresses time, so the agent service starts once the window is ingested and sees it all.
    await asyncio.gather(producer(), detector())
    results = []
    while (a := await q_alerts.get()) is not None:
        case_id, merged = await asyncio.to_thread(orchestrator.process_alert, a, run_id, scenario_id)
        results.append({"alert": a["id"], "rule": a["rule_id"], "case": case_id, "merged": merged})
    return results


def run_soc(path, auto_approve=False, record=True):
    sc = telemetry.load_scenario(path)
    run_id = db.new_id("run")
    t0 = time.time()
    timings = {}
    events = telemetry.generate(sc)
    alerts = asyncio.run(_replay(events, run_id, sc["id"], timings))
    case_ids = sorted({a["case"] for a in alerts})
    if auto_approve:
        for cid in case_ids:
            for a in soar.pending(cid):
                for user, role in (ANALYST, SOC_LEAD):
                    soar.approve(a["id"], user, role)
    duration = time.time() - t0
    result = evaluate_soc(sc, case_ids, alerts)
    contain = db.one("SELECT MIN(updated) t FROM actions WHERE case_id IN (%s) AND status='executed'" %
                     ",".join("?" * len(case_ids)), case_ids) if case_ids else None
    result.update({"run_id": run_id, "scenario": sc["id"], "events": len(events), "alerts": len(alerts),
                   "cases": case_ids, "duration_s": round(duration, 2),
                   "mttd_s": round(timings["first_alert"] - t0, 2) if "first_alert" in timings else None})
    if contain and contain["t"] and "first_alert" in timings:
        result["containment_at"] = contain["t"]
    if record:
        db.insert("metrics", {"run_id": run_id, "scenario": sc["id"], "kind": "soc", "passed": int(result["passed"]),
                              "detected": int(result["detected"]), "verdict_ok": int(result["verdict_ok"]),
                              "playbook_ok": int(result["actions_ok"]), "duration": duration,
                              "details": result, "ts": db.now()})
    return result


def evaluate_soc(sc, case_ids, alerts):
    exp = sc.get("expect", {})
    cases = [orchestrator.get_case(c) for c in case_ids]
    acts = [a for c in case_ids for a in orchestrator.case_actions(c)]
    tools = {a["tool"] for a in acts}
    verdicts = {c["verdict"] for c in cases}
    want_verdict = exp.get("verdict")
    want_verdict = [want_verdict] if isinstance(want_verdict, str) else want_verdict
    detected = bool(alerts) == exp.get("detected", True)
    verdict_ok = not want_verdict or bool(verdicts & set(want_verdict))
    want_actions = set(exp.get("actions", []))
    actions_ok = want_actions <= tools and (bool(want_actions) or not acts or not exp.get("no_actions"))
    unexpected = sorted({a["tool"] for a in acts if a["status"] == "executed"} - want_actions - set(exp.get("may", [])))
    max_tier = max([a["tier"] for a in acts], default=0)
    # The agent may make an action MORE restrictive (spec: raise, never lower). That is a judgement call,
    # not a policy error, so the tier check uses the tier the gate's own rules would set.
    agent_raised = [a for a in acts if "agent requested a higher tier" in (a["tier_reasons"] or [])]
    policy_tier = max([a["base_tier"] if a in agent_raised and len(a["tier_reasons"]) == 1 else a["tier"]
                       for a in acts], default=0)
    checks = {
        "detected": detected, "verdict": verdict_ok, "actions": actions_ok, "no_wrong_auto_actions": not unexpected,
    }
    if "max_tier" in exp:
        checks["max_tier"] = policy_tier <= exp["max_tier"]
    if "status" in exp:
        want = exp["status"] if isinstance(exp["status"], list) else [exp["status"]]
        checks["status"] = all(c["status"] in want for c in cases) and bool(cases)
    if exp.get("case_kind"):
        checks["case_kind"] = any(c["kind"] == exp["case_kind"] for c in cases)
    return {"passed": all(checks.values()), "checks": checks, "detected": detected, "verdict_ok": verdict_ok,
            "actions_ok": actions_ok, "verdicts": sorted(v for v in verdicts if v), "tools": sorted(tools),
            "unexpected_auto_actions": unexpected, "max_tier": max_tier, "policy_tier": policy_tier,
            "agent_raised": [{"tool": a["tool"], "to": a["tier"]} for a in agent_raised],
            "statuses": [c["status"] for c in cases]}


# ---------------- VM ----------------

def _finding(host, cve):
    f = db.one("SELECT id FROM findings WHERE host=? AND cve=?", (host, cve))
    return lifecycle.get(f["id"]) if f else None


JOBS = {"asset_sync": lifecycle.asset_sync, "scan": lifecycle.run_scan, "vm_agent": lifecycle.vm_agent_job,
        "remediation": lifecycle.remediation_job, "verify": lifecycle.verify_job, "sla": lifecycle.sla_monitor,
        "exceptions": lifecycle.exception_expiry, "report": lifecycle.weekly_report, "cycle": lifecycle.run_cycle}


def _check(exp):
    f = _finding(exp["host"], exp["cve"])
    res = {"expect": exp, "ok": True, "notes": []}
    if f is None:
        res.update(ok=exp.get("exists") is False, notes=["finding not found"])
        return res

    def ck(name, cond, actual):
        if not cond:
            res["ok"] = False
            res["notes"].append(f"{name}: got {actual!r}")

    for k in ("state", "priority"):
        if k in exp:
            want = exp[k] if isinstance(exp[k], list) else [exp[k]]
            ck(k, f[k] in want, f[k])
    t = db.one("SELECT * FROM tickets WHERE id=?", (f["ticket_id"],)) if f["ticket_id"] else None
    if "ticket" in exp:
        ck("ticket", bool(t) == exp["ticket"], f["ticket_id"])
    if "ticket_escalated" in exp:
        ck("ticket_escalated", bool(t and t["escalated"]) == exp["ticket_escalated"], t and t["escalated"])
    for k in ("sla_warned", "sla_breached"):
        if k in exp:
            ck(k, bool(f[k]) == exp[k], f[k])
    if "proposal" in exp:
        ck("proposal", ((f.get("proposal") or {}).get("type")) == exp["proposal"], f.get("proposal"))
    if "action" in exp:
        a = db.one("SELECT * FROM actions WHERE finding_id=? ORDER BY created DESC", (f["id"],))
        for k, v in exp["action"].items():
            ck(f"action.{k}", a is not None and a[k] == v, a and a[k])
    if "ranks_above" in exp:
        other = _finding(**exp["ranks_above"])
        ck("ranks_above", other is not None and f["risk"] > other["risk"], (f["risk"], other and other["risk"]))
    return res


def run_vm(path, record=True):
    sc = yaml.safe_load(Path(path).read_text())
    run_id = db.new_id("run")
    t0 = time.time()
    log, checks = [], []
    for step in sc["steps"]:
        (op, arg), = step.items()
        if op == "job":
            out = JOBS[arg]()
            log.append({"job": arg, "result": out})
        elif op == "set_host":
            from . import inventory
            h = inventory.host(arg["host"])
            h.update({k: v for k, v in arg.items() if k != "host"})
            inventory.save_host(h)
        elif op == "advance":
            db.advance_clock(_parse_dur(arg))
            log.append({"advance": arg})
        elif op in ("approve", "reject"):
            f = _finding(arg["host"], arg["cve"])
            a = db.one("SELECT id FROM actions WHERE finding_id=? AND status='pending_approval'", (f["id"],))
            for user, role in arg.get("by", [list(ANALYST), list(SOC_LEAD)]):
                if a:
                    (soar.approve if op == "approve" else soar.reject)(a["id"], user, role)
            log.append({op: f["id"], "action": a and a["id"]})
        elif op == "accept_risk":
            f = _finding(arg["host"], arg["cve"])
            lifecycle.accept_risk(f["id"], arg["reason"], arg.get("control", ""), arg["days"], arg["approvals"])
        elif op == "confirm_fp":
            f = _finding(arg["host"], arg["cve"])
            lifecycle.confirm_false_positive(f["id"], arg.get("user", "ana"), arg.get("confirm", True))
        elif op == "kev":
            log.append({"kev": arg, "hunt_case": lifecycle.kev_update(arg)})
        elif op == "soc":
            r = run_soc(find_scenario(arg), record=False)
            log.append({"soc": arg, "cases": r["cases"]})
            checks.append({"expect": {"soc": arg}, "ok": r["passed"], "notes": [] if r["passed"] else [r["checks"]]})
        elif op == "expect":
            checks.append(_check(arg))
        elif op == "expect_case":
            c = db.one("SELECT * FROM cases WHERE kind=? ORDER BY created DESC", (arg["kind"],))
            checks.append({"expect": arg, "ok": bool(c), "notes": [] if c else ["no such case"]})
        else:
            raise ValueError(f"unknown step {op}")
    result = {"scenario": sc["id"], "run_id": run_id, "passed": all(c["ok"] for c in checks),
              "checks": checks, "log": log, "duration_s": round(time.time() - t0, 2)}
    if record:
        db.insert("metrics", {"run_id": run_id, "scenario": sc["id"], "kind": "vm", "passed": int(result["passed"]),
                              "detected": None, "verdict_ok": None, "playbook_ok": None,
                              "duration": result["duration_s"], "details": json.loads(json.dumps(result, default=str)),
                              "ts": db.now()})
    return result


def run(path_or_id, **kw):
    path = path_or_id if Path(path_or_id).exists() else find_scenario(path_or_id)
    return run_vm(path, **{k: v for k, v in kw.items() if k == "record"}) if "/vm/" in str(path) else run_soc(path, **kw)
