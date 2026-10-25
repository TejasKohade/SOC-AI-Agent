"""VM agent: checks applicability, writes the plain-English summary and fix plan, groups findings into
patch campaigns and drafts the ticket. It never changes the risk score or priority, and may only
PROPOSE a false positive when the deterministic applicability check gives evidence for it."""
import json

from . import base

TASK = """ROLE: Vulnerability management analyst.
You get one finding, its CVE record, the host record and an applicability check. Return JSON:
{"summary": "2-3 plain-English sentences: what the flaw is and why it matters on THIS host",
 "fix_plan": "concrete steps (patch version, restart needs, or compensating control if no patch)",
 "campaign": "short patch-campaign name grouping similar fixes, e.g. 'openssh 9.8 rollout'",
 "ticket_title": "...", "ticket_body": "...",
 "propose_false_positive": true or false,
 "false_positive_evidence": "required if proposing: cite the applicability check"}
Do not restate or change the risk score or priority. Only propose a false positive if the applicability
check shows the component is not running or not reachable."""


def applicability(finding, host):
    svc = next((s for s in host.get("services", []) if s["name"] == finding["package"]), None)
    if svc is None:
        return {"component_present": True, "service": None, "running": None, "reachable": None,
                "evidence": "no network service; library/desktop package installed"}
    reachable = svc["running"] and host["exposure"] != "isolated"
    return {"component_present": True, "service": svc["name"], "port": svc["port"], "running": svc["running"],
            "reachable": reachable,
            "evidence": f"service {svc['name']} on port {svc['port']} is "
                        f"{'running' if svc['running'] else 'NOT running'}; exposure={host['exposure']}"}


def _offline(finding, vuln, appl):
    fixed = vuln.get("fixed_version")
    fp = appl.get("running") is False
    return {"summary": f"{vuln['title']} ({finding['cve']}) affects {finding['package']} {finding['installed_version']} "
                       f"on {finding['host']}.",
            "fix_plan": f"Upgrade {finding['package']} to {fixed} and restart the service." if fixed else
                        f"No vendor patch. Apply a compensating control: block port {vuln.get('port')} at the host "
                        f"firewall, then file a risk exception (max 90 days) and plan replacement.",
            "campaign": f"{finding['package']} {fixed or 'compensating-control'} rollout",
            "ticket_title": f"[{finding['priority']}] {finding['cve']} on {finding['host']} ({finding['package']})",
            "ticket_body": f"{vuln['title']}. Installed {finding['installed_version']}; fixed in {fixed or 'n/a'}.",
            "propose_false_positive": fp,
            "false_positive_evidence": appl["evidence"] if fp else ""}


def run(finding, vuln, host):
    appl = applicability(finding, host)

    def validate(o):
        for k in ("summary", "fix_plan", "campaign", "ticket_title", "ticket_body"):
            base.need(o, k, str)
        o["propose_false_positive"] = bool(o.get("propose_false_positive"))
        if o["propose_false_positive"] and appl.get("running") is not False and appl.get("reachable") is not False:
            raise ValueError("cannot propose a false positive: the applicability check shows the component is "
                             "running and reachable")
        return o

    payload = "\n".join([
        f"FINDING: {json.dumps({k: finding[k] for k in ('id', 'host', 'cve', 'package', 'installed_version', 'port', 'risk', 'priority')})}",
        f"CVE RECORD: {json.dumps(vuln)}",
        f"HOST: {json.dumps({k: host.get(k) for k in ('name', 'os', 'role', 'environment', 'criticality', 'exposure', 'owner', 'services')})}",
        f"APPLICABILITY CHECK: {json.dumps(appl)}",
    ])
    out, meta = base.run("vm-agent", None, TASK, payload, validate, lambda: _offline(finding, vuln, appl))
    out["applicability"] = appl
    return out, meta
