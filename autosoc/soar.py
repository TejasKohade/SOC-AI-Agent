"""SOAR: YAML playbook runner behind a risk-tier approval gate.

The tier of every action comes from the playbook, never from the AI. The gate can only raise it:
when the agent asks, when confidence is low, when the asset is critical, when the evidence comes
from a single source, or when a playbook `raise_if` rule matches (admin/exec user, server host).
Tier 0-1 run at once; tier 2 needs one approver; tier 3 needs an analyst and a SOC lead.
"""
from functools import lru_cache

import yaml

from . import config, db, inventory
from .tools import ResponseClient

ROLES_FOR_TIER = {2: [{"analyst", "soc_lead"}], 3: [{"analyst"}, {"soc_lead"}]}


@lru_cache
def catalogue():
    out = {}
    for p in sorted(config.PLAYBOOK_DIR.glob("*.yml")):
        pb = yaml.safe_load(p.read_text())
        out[pb["id"]] = pb
    return out


def catalogue_summary():
    return [{"id": pb["id"], "name": pb["name"], "trigger": pb["trigger"], "mitre": pb.get("mitre", []),
             "params": pb.get("params", {}),
             "steps": [{"id": s["id"], "tool": s["tool"], "tier": s["tier"], "when": s.get("when")}
                       for s in pb["steps"]]}
            for pb in catalogue().values()]


def _render(template, values):
    out = {}
    for k, v in template.items():
        if isinstance(v, str) and v.startswith("{") and v.endswith("}") and v.count("{") == 1:
            key = v[1:-1]
            if values.get(key) in (None, "", []):
                return None  # a required value is missing: skip the step
            out[k] = values[key]
        else:
            out[k] = v
    return out


def expand(playbook_id, params):
    """Turn a playbook + filled parameters into concrete action steps."""
    pb = catalogue()[playbook_id]
    steps = []
    for s in pb["steps"]:
        if s.get("when") and not params.get(s["when"]):
            continue
        items = params.get(s["foreach"]) if s.get("foreach") else [None]
        if isinstance(items, str):
            items = [items]
        for item in items or []:
            rendered = _render(s["params"], {**params, "item": item})
            if rendered is None:
                continue
            steps.append({"step": s["id"], "tool": s["tool"], "params": rendered, "base_tier": s["tier"],
                          "raise_if": s.get("raise_if", {}),
                          "auto_if_high_confidence": s.get("auto_if_high_confidence", False)})
    return steps


def compute_tier(step, ctx):
    """ctx: verdict, confidence, host, user, target_user, evidence_sources, agent_raise{step: tier}."""
    base = step["base_tier"]
    tier, reasons = base, []

    def bump(to, why):
        nonlocal tier
        if to > tier:
            tier = min(3, to)
            reasons.append(why)

    h = inventory.host(ctx.get("host") or "") or {}
    roles = {"user_role": (inventory.user(ctx.get("user") or "") or {}).get("role"),
             "target_user_role": (inventory.user(ctx.get("target_user") or "") or {}).get("role"),
             "host_role": h.get("role")}
    for key, values in step.get("raise_if", {}).items():
        if roles.get(key) in values:
            bump(3, f"{key}={roles[key]}")
    want = (ctx.get("agent_raise") or {}).get(step["step"])
    if want:
        bump(int(want), "agent requested a higher tier")
    if base >= 1:
        if ctx.get("confidence") is not None and ctx["confidence"] < config.CONFIDENCE_FLOOR:
            bump(tier + 1, f"confidence {ctx['confidence']:.2f} < {config.CONFIDENCE_FLOOR}")
        if h.get("criticality") == "critical":
            bump(tier + 1, "asset tagged critical")
        if ctx.get("evidence_sources") is not None and len(ctx["evidence_sources"]) <= 1:
            bump(tier + 1, "evidence from a single source")
    return tier, reasons


def submit(case_id, steps, ctx, playbook=None, finding_id=None, actor="response-agent"):
    """Register actions; run the ones the gate allows, park the rest for approval."""
    ids = []
    for s in steps:
        tier, reasons = s.get("tier_override") or compute_tier(s, ctx)
        aid = db.new_id("act")
        rb = ResponseClient.rollback_tool(s["tool"])
        db.insert("actions", {
            "id": aid, "case_id": case_id, "finding_id": finding_id, "playbook": playbook, "step": s["step"],
            "tool": s["tool"], "params": s["params"], "tier": tier, "base_tier": s["base_tier"],
            "tier_reasons": reasons, "status": "planned", "approvals": [],
            "rollback": {"tool": rb, "params": s["params"]} if rb else None,
            "created": db.now(), "updated": db.now()})
        auto_hc = (tier == 2 and s.get("auto_if_high_confidence") and not reasons
                   and ctx.get("verdict") == "malicious" and (ctx.get("confidence") or 0) >= 0.95)
        if tier <= 1 or auto_hc:
            why = "tier 0-1: automatic" if tier <= 1 else "tier 2 auto: high-confidence malware"
            db.audit(case_id, "approval-gate", "decision", {"action": aid, "tool": s["tool"], "tier": tier,
                                                            "decision": "auto", "why": why})
            execute(aid, actor="playbook-runner")
        else:
            db.update("actions", "id", aid, {"status": "pending_approval"})
            db.audit(case_id, "approval-gate", "decision", {"action": aid, "tool": s["tool"], "tier": tier,
                                                            "decision": "needs_approval", "reasons": reasons})
        ids.append(aid)
    return ids


def execute(action_id, actor="playbook-runner"):
    a = get(action_id)
    try:
        result = ResponseClient().call(a["tool"], a["params"])
        status = "executed"
    except Exception as e:  # mock API error: record it, never crash the case
        result, status = {"error": str(e)}, "failed"
    db.update("actions", "id", action_id, {"status": status, "result": result, "updated": db.now()})
    db.audit(a["case_id"], actor, "action", {"action": action_id, "tool": a["tool"], "params": a["params"],
                                             "status": status, "result": result, "finding": a["finding_id"]})
    return get(action_id)


def get(action_id):
    a = db.one("SELECT * FROM actions WHERE id=?", (action_id,))
    if a:
        for k in ("params", "approvals", "rollback", "result", "tier_reasons"):
            a[k] = db.loads(a[k], a[k])
    return a


def _approved(a):
    yes = [x for x in a["approvals"] if x["decision"] == "approve"]
    users = {x["user"] for x in yes}
    roles = {x["role"] for x in yes}
    if a["tier"] == 3:
        return {"analyst", "soc_lead"} <= roles and len(users) >= 2
    return bool(roles & {"analyst", "soc_lead"})


def approve(action_id, user, role):
    a = get(action_id)
    if a["status"] != "pending_approval":
        return a
    a["approvals"].append({"user": user, "role": role, "decision": "approve", "ts": db.now()})
    db.update("actions", "id", action_id, {"approvals": a["approvals"], "updated": db.now()})
    db.audit(a["case_id"], f"{role}:{user}", "approval", {"action": action_id, "decision": "approve"})
    if _approved(a):
        a = execute(action_id, actor=f"playbook-runner (approved by {user})")
        _after_decision(a)
    return get(action_id)


def reject(action_id, user, role, reason=""):
    a = get(action_id)
    if a["status"] != "pending_approval":
        return a
    a["approvals"].append({"user": user, "role": role, "decision": "reject", "reason": reason, "ts": db.now()})
    db.update("actions", "id", action_id, {"approvals": a["approvals"], "status": "rejected", "updated": db.now()})
    db.audit(a["case_id"], f"{role}:{user}", "approval", {"action": action_id, "decision": "reject",
                                                           "reason": reason})
    _after_decision(get(action_id))
    return get(action_id)


def rollback(action_id, user="analyst"):
    a = get(action_id)
    if a["status"] != "executed" or not a["rollback"]:
        return a
    try:
        ResponseClient().call(a["rollback"]["tool"], a["rollback"]["params"])
        db.update("actions", "id", action_id, {"status": "rolled_back", "updated": db.now()})
        db.audit(a["case_id"], user, "rollback", {"action": action_id, "tool": a["rollback"]["tool"]})
    except Exception as e:
        db.audit(a["case_id"], user, "rollback_failed", {"action": action_id, "error": str(e)})
    return get(action_id)


def _after_decision(a):
    if a["finding_id"]:
        from .vm import lifecycle
        lifecycle.on_action_done(a)
    if a["case_id"]:
        from .agents import orchestrator
        orchestrator.resume(a["case_id"])


def pending(case_id=None):
    sql = "SELECT id FROM actions WHERE status='pending_approval'"
    args = ()
    if case_id:
        sql += " AND case_id=?"
        args = (case_id,)
    return [get(r["id"]) for r in db.query(sql + " ORDER BY created", args)]


def escalate_stale():
    """Tier 2 escalates after 15 min unanswered; tier 3 never auto-runs and keeps paging."""
    out = []
    for a in pending():
        if not a["escalated"] and db.now() - a["created"] > config.APPROVAL_ESCALATE_S:
            db.update("actions", "id", a["id"], {"escalated": 1})
            db.audit(a["case_id"], "approval-gate", "escalation",
                     {"action": a["id"], "tier": a["tier"],
                      "to": "SOC lead" if a["tier"] == 2 else "SOC lead + on-call (paging)"})
            out.append(a["id"])
    return out
