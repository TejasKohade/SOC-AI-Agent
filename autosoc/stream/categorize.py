"""Categorise every event, whatever its origin (synthetic feed, real OTRF capture, or /ingest).

Each event is tagged with:
  event.source_type  - which kind of sensor it came from (sshd, sysmon, firewall, dns, email, ...)
  event.category     - a coarse bucket an analyst thinks in (authentication, process, network, ...)
This is the step that turns a mixed raw stream into something that can be filtered and counted.
"""

# event.action -> (source_type, category). Order does not matter; first exact match wins.
ACTION_MAP = {
    "ssh_login_failed": ("sshd", "authentication"),
    "ssh_login_success": ("sshd", "authentication"),
    "logon_success": ("windows-security", "authentication"),
    "logon_failed": ("windows-security", "authentication"),
    "process_start": ("sysmon", "process"),
    "process_access": ("sysmon", "process"),
    "network_connection": ("sysmon", "network"),
    "network_flow": ("firewall", "network"),
    "dns_query": ("dns", "network"),
    "user_created": ("windows-security", "identity"),
    "added_to_group": ("windows-security", "identity"),
    "email_delivered": ("email-gateway", "email"),
    "user_reported_phish": ("email-gateway", "email"),
    "url_clicked": ("proxy", "web"),
    "ids_alert": ("suricata", "network"),
    "syslog_message": ("syslog", "system"),
}

MODULE_DEFAULT = {
    "auditd": ("auditd", "authentication"), "sysmon": ("sysmon", "process"),
    "windows": ("windows-security", "authentication"), "email": ("email-gateway", "email"),
    "dns": ("dns", "network"), "firewall": ("firewall", "network"), "suricata": ("suricata", "network"),
    "syslog": ("syslog", "system"),
}

SOURCE_TYPES = sorted({v[0] for v in ACTION_MAP.values()} | {v[0] for v in MODULE_DEFAULT.values()})
CATEGORIES = ["authentication", "identity", "process", "network", "email", "web", "system", "other"]


def categorize(ev):
    """Return (source_type, category) for one flat event; also stamps the fields onto it."""
    action = ev.get("event.action")
    module = ev.get("event.module")
    src, cat = ACTION_MAP.get(action) or MODULE_DEFAULT.get(module) or ("unknown", "other")
    ev["event.source_type"] = src
    ev["event.category"] = cat
    return src, cat


def label(ev):
    """Short human line for the live console, e.g. 'sshd/authentication on web-01'."""
    return f"{ev.get('event.source_type', '?')}/{ev.get('event.category', '?')} on {ev.get('host.name', '?')}"
