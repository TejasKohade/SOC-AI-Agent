"""Investigation agent: pivots through logs (deterministic tool calls), then the LLM builds the story:
timeline, scope, IOCs and ATT&CK mapping."""
import ipaddress
import json
import re

from . import base
from ..tools import BudgetExceeded, ToolBox

TASK = """ROLE: Tier-2 incident investigator.
Using the pivot results, build the story of what happened. Return JSON:
{"summary": "3-5 sentence narrative",
 "timeline": [{"time": "...", "event_id": "<id from input>", "description": "..."}],
 "affected_hosts": [...], "affected_users": [...],
 "iocs": [{"type": "ip|domain|url|sha256|account|task", "value": "..."}],
 "mitre": [{"id": "T....", "name": "..."}],
 "root_cause": "one sentence",
 "root_cause_cve": "CVE id if a known vulnerability was the entry point, else null"}
Keep the timeline to the 3-10 most important events, in time order. Only use ids, hosts, users and IOCs
present in the input."""

IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL = re.compile(r"https?://[^\s'\"<>)]+", re.I)

_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]

MITRE_NAMES = {"T1110": "Brute Force", "T1059.001": "PowerShell", "T1003": "OS Credential Dumping",
               "T1136": "Create Account", "T1053": "Scheduled Task/Job", "T1566": "Phishing",
               "T1190": "Exploit Public-Facing Application", "T1048": "Exfiltration Over Alternative Protocol",
               "T1078": "Valid Accounts", "T1105": "Ingress Tool Transfer"}


def _is_internal(ip):
    """RFC 1918 + loopback only. (ipaddress.is_private also covers the documentation ranges the
    mock attackers use, such as 203.0.113.0/24, which must count as external here.)"""
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return a.is_loopback or any(a in n for n in _INTERNAL)


def extract_facts(alert_events, context_events, alerts):
    """Deterministic facts the response planner needs (no LLM)."""
    f = {"ips": set(), "domains": set(), "urls": set(), "hashes": set(), "message_ids": [], "clicked_users": set()}
    first = alert_events[0]["raw"] if alert_events else {}
    f["host"] = first.get("host.name")
    f["user"] = first.get("user.name")
    f["process"] = first.get("process.name")
    f["src_ip"] = first.get("source.ip")
    alert_ips = {e["raw"].get(k) for e in alert_events for k in ("source.ip", "destination.ip")} - {None}
    alert_procs = {e["raw"].get("process.name") for e in alert_events} - {None}

    def related(r):
        """Context events only contribute IOCs when tied to the attack (same IP, process or email)."""
        return (r.get("source.ip") in alert_ips or r.get("destination.ip") in alert_ips
                or r.get("process.name") in alert_procs or r.get("event.module") == "email")

    for e in alert_events + [c for c in context_events if related(c["raw"])]:
        r = e["raw"]
        for k in ("source.ip", "destination.ip"):
            if r.get(k) and not _is_internal(str(r[k])):
                f["ips"].add(r[k])
        if r.get("url.full"):
            f["urls"].add(r["url.full"])
        if r.get("url.domain"):
            f["domains"].add(r["url.domain"])
        if r.get("file.hash.sha256"):
            f["hashes"].add(r["file.hash.sha256"])
        cmd = str(r.get("process.command_line", ""))
        decoded = base.decode_powershell(cmd) or ""
        for text in (cmd, decoded):
            for u in URL.findall(text):
                f["urls"].add(u.rstrip("')\";"))
            for ip in IP.findall(text):
                if not _is_internal(ip):
                    f["ips"].add(ip)
        if decoded:
            f["decoded_command"] = decoded
        m = re.search(r'/tn\s+"?([^"/]+?)"?\s+/', cmd, re.I)
        if m:
            f["task"] = m.group(1).strip()
        m = re.search(r"net\s+user\s+(\S+)\s+\S*\s*/add", cmd, re.I)
        if m:
            f["target_user"] = m.group(1)
        if r.get("event.action") == "url_clicked":
            f["clicked_users"].add(r.get("user.name"))
    for u in f["urls"]:
        m = re.match(r"https?://([^/:]+)", u)
        if m and not IP.fullmatch(m.group(1)):
            f["domains"].add(m.group(1))
    # brute force: did any login from the attacking IP succeed?
    if f["src_ip"]:
        ok = [e for e in context_events if e["raw"].get("source.ip") == f["src_ip"]
              and e["raw"].get("event.action") in ("ssh_login_success", "logon_success")]
        f["login_success"] = bool(ok)
        if ok:
            f["user"] = ok[-1]["raw"].get("user.name")
    f["cves"] = sorted({c for a in alerts for c in a.get("cves", [])})
    return f


def pivot(case, alerts, alert_events):
    tb = ToolBox("investigation", case["id"])
    t0 = min(e["ts"] for e in alert_events) - 1800
    t1 = max(e["ts"] for e in alert_events) + 1800
    ctx, seen = [], {e["id"] for e in alert_events}

    def add(rows):
        for r in rows:
            if r["id"] not in seen:
                seen.add(r["id"])
                ctx.append(r)

    first = alert_events[0]["raw"]
    try:
        if first.get("host.name") and first.get("event.module") != "email":
            add(tb.call("siem.search", host=first["host.name"], since=t0, until=t1, limit=150))
        if first.get("source.ip"):
            add(tb.call("siem.search", src_ip=first["source.ip"], since=t0, until=t1 + 3600))
        if first.get("user.name") and first.get("event.module") != "email":
            add(tb.call("siem.search", user=first["user.name"], since=t0, until=t1, limit=100))
        facts = extract_facts(alert_events, ctx, alerts)
        for d in sorted(facts["domains"])[:3]:
            add(tb.call("siem.search", text=d, since=t0 - 86400, until=t1 + 3600))
        if facts["urls"] or facts["domains"]:
            hits = []
            for d in sorted(facts["domains"])[:2]:
                hits += tb.call("email.search", url=d)
            facts["message_ids"] = sorted({h["message_id"] for h in hits if h.get("message_id")})
            facts["recipients"] = sorted({h["to"] for h in hits if h.get("to")})
        facts = {**extract_facts(alert_events, ctx, alerts), "message_ids": facts.get("message_ids", []),
                 "recipients": facts.get("recipients", [])}
        alert_facts = extract_facts(alert_events, [], alerts)
        primary = sorted(alert_facts["ips"] | alert_facts["domains"] | alert_facts["hashes"])
        rest = sorted((facts["ips"] | facts["domains"] | facts["hashes"]) - set(primary))
        intel = []
        for ind in (primary + rest)[:6]:
            intel.append(tb.call("intel.lookup", indicator=ind))
        facts["intel"] = intel
        bad = {i["indicator"] for i in intel if i.get("verdict") == "malicious"}
        c2 = [ip for ip in facts["ips"] if ip in bad and ip != facts.get("src_ip")]
        facts["c2_ip"] = c2[0] if c2 else None
        bad_domains = [d for d in facts["domains"] if d in bad]
        facts["domain"] = bad_domains[0] if bad_domains else (sorted(facts["domains"])[0] if facts["domains"] else None)
    except BudgetExceeded:
        facts = extract_facts(alert_events, ctx, alerts)
        facts["budget_exhausted"] = True
    ctx.sort(key=lambda e: e["ts"])
    return ctx, facts


def _jsonable(facts):
    return {k: sorted(v) if isinstance(v, set) else v for k, v in facts.items()}


def _offline(case, alert_events, ctx, facts):
    evs = sorted(alert_events + [e for e in ctx if e["raw"].get("source.ip") == facts.get("src_ip")
                                 or e["raw"].get("process.name")], key=lambda e: e["ts"])
    tl = [{"time": base.iso(e["ts"]), "event_id": e["id"],
           "description": f"{e['raw'].get('event.action')} on {e['raw'].get('host.name')}"
                          f" by {e['raw'].get('user.name')}"} for e in evs[:3] + evs[-3:]]
    tl = list({t["event_id"]: t for t in tl}.values())
    mitre = [{"id": m, "name": MITRE_NAMES.get(m, m)} for m in json.loads(case["mitre"] or "[]")]
    iocs = ([{"type": "ip", "value": i} for i in sorted(facts["ips"])] +
            [{"type": "domain", "value": d} for d in sorted(facts["domains"])] +
            [{"type": "sha256", "value": h} for h in sorted(facts["hashes"])])
    return {"summary": f"{case['title']}. {len(alert_events)} alert event(s), {len(ctx)} related events. "
                       f"Indicators: {', '.join(i['value'] for i in iocs) or 'none'}.",
            "timeline": tl, "affected_hosts": sorted({e["raw"].get("host.name") for e in alert_events} - {None}),
            "affected_users": sorted({e["raw"].get("user.name") for e in alert_events} - {None}),
            "iocs": iocs, "mitre": mitre, "root_cause": "See timeline.",
            "root_cause_cve": facts["cves"][0] if facts.get("cves") else None}


def run(case, alerts, alert_events, analyst_note=None):
    ctx, facts = pivot(case, alerts, alert_events)
    ids = {e["id"] for e in alert_events + ctx}

    def validate(o):
        base.need(o, "summary", str)
        tl = base.need(o, "timeline", list)
        for t in tl:
            if t.get("event_id") not in ids:
                raise ValueError(f"timeline cites unknown event id {t.get('event_id')}")
        o.setdefault("mitre", [])
        o.setdefault("iocs", [])
        o.setdefault("affected_hosts", [])
        o.setdefault("affected_users", [])
        if o.get("root_cause_cve") and o["root_cause_cve"] not in facts.get("cves", []):
            o["root_cause_cve"] = None  # only CVEs actually named by the alerts count
        return o

    jf = _jsonable(facts)
    payload = "\n".join([
        f"CASE: {case['title']}",
        f"ALERTS: {json.dumps([{k: a[k] for k in ('rule_title', 'mitre', 'host', 'user', 'src_ip', 'cves')} for a in alerts])}",
        f"DETERMINISTIC FACTS (from pivots): {json.dumps({k: v for k, v in jf.items() if k not in ('intel', 'decoded_command')})}",
        f"DECODED COMMAND: {base.wrap('process.decoded_command', jf['decoded_command']) if jf.get('decoded_command') else 'n/a'}",
        f"THREAT INTEL: {json.dumps(jf.get('intel', []))}",
        f"ANALYST NOTE: {analyst_note}" if analyst_note else "",
        "ALERT EVENTS:", base.present_events(alert_events, 15),
        "RELATED EVENTS (pivots by host, user and source IP):", base.present_events(ctx, 30),
    ])
    out, meta = base.run("investigation", case["id"], TASK, payload, validate,
                         lambda: _offline(case, alert_events, ctx, facts))
    out["facts"] = jf
    return out, meta
