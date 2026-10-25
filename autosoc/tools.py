"""Tool access for agents and the playbook runner.

Agents get a read-only ToolBox: each agent may call only the tools on its allowlist, every call
is audited on the case, and calls count against the per-alert budget. Only the playbook runner
(soar.py) holds a ResponseClient that can reach the state-changing mock endpoints.
"""
from functools import lru_cache

import httpx

from . import config, db, inventory


class BudgetExceeded(Exception):
    pass


class ToolNotAllowed(Exception):
    pass


@lru_cache
def http():
    """HTTP client for the mock APIs: in-process by default, or a running server via MOCK_BASE_URL."""
    if config.MOCK_BASE_URL:
        return httpx.Client(base_url=config.MOCK_BASE_URL, timeout=30)
    from fastapi.testclient import TestClient

    from .mocks.app import app
    return TestClient(app)


def _get(path, **params):
    r = http().get(path, params=params)
    r.raise_for_status()
    return r.json()


# ---------------- read-only tools ----------------

def siem_search(host=None, user=None, src_ip=None, text=None, since=None, until=None, limit=200):
    sql, args = "SELECT id, ts, source, host, user, action, src_ip, dst_ip, raw FROM events WHERE 1=1", []
    for col, val in (("host", host), ("user", user), ("src_ip", src_ip)):
        if val:
            sql += f" AND {col}=?"
            args.append(val)
    if text:
        sql += " AND raw LIKE ?"
        args.append(f"%{text}%")
    if since:
        sql += " AND ts>=?"
        args.append(since)
    if until:
        sql += " AND ts<=?"
        args.append(until)
    sql += " ORDER BY ts LIMIT ?"
    args.append(limit)
    rows = db.query(sql, args)
    for r in rows:
        r["raw"] = db.loads(r["raw"], {})
    return rows


def intel_lookup(indicator):
    return _get("/intel/reputation", indicator=indicator)


def host_lookup(name):
    h = inventory.host(name)
    if not h:
        return {"name": name, "known": False, "note": "not in inventory (possible shadow IT)"}
    edr = _get(f"/edr/hosts/{name}")
    return {**{k: h.get(k) for k in ("name", "ip", "os", "role", "environment", "criticality",
                                     "exposure", "owner")}, "known": True, "isolated": edr["isolated"]}


def user_lookup(name):
    u = inventory.user(name)
    return {**(u or {"name": name}), "known": u is not None, **_get(f"/idp/users/{name}")}


def similar_cases(rule_id=None, host=None, limit=5):
    rows = db.query("SELECT c.id, c.title, c.verdict, c.confidence, c.status FROM cases c "
                    "WHERE c.status IN ('closed','false_positive') AND (c.host=? OR c.title LIKE ?) "
                    "ORDER BY c.updated DESC LIMIT ?", (host, f"%{rule_id or '~'}%", limit))
    return rows


def open_findings(host):
    return db.query("SELECT id, cve, priority, risk, state FROM findings WHERE host=? AND state NOT IN "
                    "('closed','false_positive')", (host,))


def signins(user):
    return _get(f"/idp/signins/{user}")


def email_search(url="", sender=""):
    return _get("/email/search", url=url, sender=sender)


READ_TOOLS = {
    "siem.search": siem_search,
    "intel.lookup": intel_lookup,
    "inventory.host": host_lookup,
    "inventory.user": user_lookup,
    "cases.similar": similar_cases,
    "vm.open_findings": open_findings,
    "idp.signins": signins,
    "email.search": email_search,
}

# Least privilege: what each agent may call
AGENT_TOOLS = {
    "orchestrator": {"intel.lookup", "inventory.host", "inventory.user", "vm.open_findings"},
    "triage": {"siem.search", "inventory.host", "inventory.user", "cases.similar", "vm.open_findings"},
    "investigation": {"siem.search", "inventory.host", "inventory.user", "intel.lookup", "idp.signins",
                      "email.search"},
    "response": set(),      # reads the playbook catalogue only; hands plans to the approval gate
    "reporting": set(),
    "vm": {"inventory.host"},
}


class ToolBox:
    def __init__(self, agent, case_id):
        self.agent, self.case_id = agent, case_id

    def call(self, tool, **kwargs):
        name = tool
        if name not in AGENT_TOOLS.get(self.agent, set()):
            db.audit(self.case_id, self.agent, "tool_denied", {"tool": name, "args": kwargs})
            raise ToolNotAllowed(f"{self.agent} may not call {name}")
        if self.case_id:
            row = db.one("SELECT tool_calls FROM cases WHERE id=?", (self.case_id,))
            if row and row["tool_calls"] >= config.MAX_TOOL_CALLS_PER_ALERT:
                raise BudgetExceeded("tool-call budget exhausted")
            db.execute("UPDATE cases SET tool_calls=tool_calls+1 WHERE id=?", (self.case_id,))
        result = READ_TOOLS[name](**kwargs)
        summary = result if not isinstance(result, list) else {"rows": len(result)}
        db.audit(self.case_id, self.agent, "tool_call", {"tool": name, "args": kwargs, "result": summary})
        return result


# ---------------- state-changing tools: playbook runner only ----------------

RESPONSE_ENDPOINTS = {
    # tool name: (endpoint, rollback tool or None)
    "edr.isolate_host": ("/edr/isolate", "edr.unisolate_host"),
    "edr.unisolate_host": ("/edr/unisolate", None),
    "edr.kill_process": ("/edr/kill_process", None),
    "edr.remove_persistence": ("/edr/remove_persistence", "edr.restore_persistence"),
    "edr.restore_persistence": ("/edr/restore_persistence", None),
    "firewall.block_ip": ("/firewall/block", "firewall.unblock_ip"),
    "firewall.unblock_ip": ("/firewall/unblock", None),
    "firewall.block_domain": ("/firewall/block", "firewall.unblock_domain"),
    "firewall.unblock_domain": ("/firewall/unblock", None),
    "firewall.block_port": ("/firewall/block", "firewall.unblock_port"),
    "firewall.unblock_port": ("/firewall/unblock", None),
    "idp.disable_user": ("/idp/disable", "idp.enable_user"),
    "idp.enable_user": ("/idp/enable", None),
    "idp.revoke_sessions": ("/idp/revoke_sessions", None),
    "idp.force_password_reset": ("/idp/force_password_reset", None),
    "email.quarantine": ("/email/quarantine", "email.release"),
    "email.release": ("/email/release", None),
    "patch.apply": ("/patch/apply", "patch.rollback"),
    "patch.rollback": ("/patch/rollback", None),
    "patch.control": ("/patch/control", "patch.control_remove"),
    "patch.control_remove": ("/patch/control/remove", None),
}

_KIND = {"firewall.block_ip": "ip", "firewall.unblock_ip": "ip", "firewall.block_domain": "domain",
         "firewall.unblock_domain": "domain", "firewall.block_port": "port", "firewall.unblock_port": "port"}


class ResponseClient:
    def call(self, tool, params):
        endpoint, _ = RESPONSE_ENDPOINTS[tool]
        body = dict(params)
        if tool in _KIND:
            body["kind"] = _KIND[tool]
        r = http().post(endpoint, json=body)
        r.raise_for_status()
        return r.json()

    @staticmethod
    def rollback_tool(tool):
        return RESPONSE_ENDPOINTS[tool][1]


def tickets_api():
    return http()
