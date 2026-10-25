"""Deterministic, explainable risk score:  risk = CVSS x w_asset x w_exposure + 3*KEV + 5*EPSS."""

W_ASSET = {"critical": 1.5, "high": 1.2, "normal": 1.0, "low": 0.7}
W_EXPOSURE = {"internet-facing": 1.3, "internal": 1.0, "isolated": 0.8}
SLA_HOURS = {"P1": 72, "P2": 7 * 24, "P3": 30 * 24, "P4": 90 * 24}
EXCEPTION_APPROVERS = {"P1": {"soc_lead", "owner"}, "P2": {"soc_lead"}, "P3": {"owner"}, "P4": {"owner"}}


def risk(cvss, criticality, exposure, kev, epss):
    return round(cvss * W_ASSET.get(criticality, 1.0) * W_EXPOSURE.get(exposure, 1.0) + 3 * int(bool(kev)) + 5 * epss, 2)


def priority(r, kev, epss, criticality, exposure):
    """First match wins."""
    if (kev and (exposure == "internet-facing" or criticality == "critical")) or r >= 18:
        return "P1"
    if kev or epss >= 0.5 or r >= 12:
        return "P2"
    if r >= 6:
        return "P3"
    return "P4"


def score(vuln, host):
    r = risk(vuln["cvss"], host["criticality"], host["exposure"], vuln["kev"], vuln["epss"])
    p = priority(r, vuln["kev"], vuln["epss"], host["criticality"], host["exposure"])
    return {"risk": r, "priority": p, "sla_hours": SLA_HOURS[p],
            "explain": f"{vuln['cvss']} x {W_ASSET.get(host['criticality'])} ({host['criticality']}) x "
                       f"{W_EXPOSURE.get(host['exposure'])} ({host['exposure']}) + 3x{int(bool(vuln['kev']))} (KEV) "
                       f"+ 5x{vuln['epss']} (EPSS) = {r} -> {p}"}
