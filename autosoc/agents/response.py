"""Response agent: picks a playbook and fills its parameters. It never acts: the plan goes to the
approval gate, which sets the tier from the playbook (the agent may only ask for a higher tier)."""
import json

from . import base
from .. import soar

TASK = """ROLE: Incident responder (planning only - you cannot execute anything).
Choose the ONE playbook from the catalogue that fits this case and fill its parameters using ONLY values
present in the case facts. Return JSON:
{"playbook": "<playbook id>",
 "params": {"<param>": <value from the facts>, ...},
 "raise_tier": {"<step id>": 2 or 3},   // optional; only to make a step MORE restrictive, with a reason
 "raise_reason": "",
 "rationale": "1-2 sentences"}
Rules: list-valued params (message_ids, clicked_users) must be JSON lists. Boolean params are true/false.
Omit optional params that do not apply."""

RULE_TO_PLAYBOOK = {}


def _offline(case, facts, rule_ids):
    if not RULE_TO_PLAYBOOK:
        for pb in soar.catalogue().values():
            for r in pb.get("rules", []):
                RULE_TO_PLAYBOOK[r] = pb["id"]
    pid = next((RULE_TO_PLAYBOOK[r] for r in rule_ids if r in RULE_TO_PLAYBOOK), "malicious_ip")
    spec = soar.catalogue()[pid]["params"]
    params = {k: facts.get(k) for k in spec if facts.get(k) not in (None, "", [])}
    if pid == "suspicious_powershell" or pid == "malware_endpoint":
        params.setdefault("process", facts.get("process"))
    if pid == "data_exfiltration":
        params["dst_ip"] = next(iter(facts.get("ips", [])), None)
    return {"playbook": pid, "params": params, "raise_tier": {}, "raise_reason": "",
            "rationale": f"Rule {rule_ids[0] if rule_ids else '?'} maps to playbook {pid}."}


def _values(facts):
    """Every scalar that appears in the facts: parameter values must come from here."""
    out = set()

    def walk(v):
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, (list, tuple, set)):
            for x in v:
                walk(x)
        elif v not in (None, ""):
            out.add(str(v).lower())
    walk(facts)
    return out


def run(case, investigation, rule_ids):
    facts = investigation["facts"]
    allowed = _values(facts)
    cat = soar.catalogue()

    def validate(o):
        pid = base.need(o, "playbook", str, set(cat))
        params = base.need(o, "params", dict)
        spec = cat[pid]["params"]
        for k in list(params):
            if k not in spec:
                params.pop(k)  # unknown params are dropped, not executed
        for k, s in spec.items():
            if s.get("required") and params.get(k) in (None, "", []):
                raise ValueError(f"playbook {pid} needs parameter '{k}'")
        for k, v in params.items():
            for item in (v if isinstance(v, list) else [v]):
                if isinstance(item, bool) or item is None:
                    continue
                if str(item).lower() not in allowed:
                    raise ValueError(f"parameter {k}={item!r} does not appear in the case facts")
        raise_tier = {k: int(v) for k, v in (o.get("raise_tier") or {}).items() if int(v) in (2, 3)}
        o["raise_tier"] = raise_tier
        return o

    payload = "\n".join([
        f"CASE: {case['title']}  verdict={case['verdict']}  confidence={case['confidence']}",
        f"RULES: {rule_ids}",
        f"INVESTIGATION SUMMARY: {investigation['summary']}",
        f"FACTS: {json.dumps({k: v for k, v in facts.items() if k not in ('intel', 'decoded_command')})}",
        f"PLAYBOOK CATALOGUE: {json.dumps(soar.catalogue_summary())}",
    ])
    return base.run("response", case["id"], TASK, payload, validate, lambda: _offline(case, facts, rule_ids))
