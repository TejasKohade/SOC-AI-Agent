"""Behaviour-based detection: flag what deviates from a learned baseline, not just known signatures.

Baselines are built from the normal events already stored (who logs in where, from which networks,
which processes a host runs). An event that breaks the baseline raises an alert the same shape the
Sigma engine produces, so the rest of the pipeline treats both kinds identically.

This is deliberately simple (counts and sets, no ML) but it catches things signatures do not: a login
from a never-seen country/network, a user on a host they have never touched, a rare process, or an
admin action outside business hours.
"""
import datetime as dt
import ipaddress

from .. import db

MIN_HISTORY = 20          # need at least this many prior events before trusting a baseline
MIN_USER_LOGINS = 5       # and this many logins for a given user before judging that user
BUSINESS_HOURS = range(7, 20)


_RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _net(ip):
    # Only RFC-1918 and loopback count as internal. ipaddress.is_private also covers the
    # documentation ranges (203.0.113.0/24, 198.51.100.0/24) our mock attackers use, which must
    # read as external here.
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    if a.is_loopback or any(a in n for n in _RFC1918):
        return "internal"
    return ".".join(str(ip).split(".")[:2])  # /16-ish bucket stands in for "network/geo"


class Baselines:
    """Learned from history; ask() returns a list of anomaly alerts for one event."""

    def __init__(self):
        self.user_nets = {}        # user -> set of source networks seen
        self.user_hosts = {}       # user -> set of hosts logged into
        self.host_procs = {}       # host -> set of process names seen
        self.user_logins = {}      # user -> count of logins seen (confidence in the baseline)
        self.total = 0

    def learn_from_db(self, run_id=None):
        q = "SELECT user, host, src_ip, action, raw FROM events"
        rows = db.query(q)
        for r in rows:
            self._learn(r["user"], r["host"], r["src_ip"], r["action"], db.loads(r["raw"], {}))

    def _learn(self, user, host, src_ip, action, raw):
        self.total += 1
        if action in ("ssh_login_success", "logon_success") and user:
            self.user_nets.setdefault(user, set()).add(_net(src_ip))
            self.user_hosts.setdefault(user, set()).add(host)
            self.user_logins[user] = self.user_logins.get(user, 0) + 1
        if action == "process_start" and host:
            self.host_procs.setdefault(host, set()).add((raw.get("process.name") or "").lower())

    def observe(self, ev):
        """Update the baseline with an event after it has been scored (so it learns over time)."""
        self._learn(ev.get("user.name"), ev.get("host.name"), ev.get("source.ip"),
                    ev.get("event.action"), ev)

    def ask(self, ev):
        alerts = []
        user, host = ev.get("user.name"), ev.get("host.name")
        action = ev.get("event.action")
        ts = ev.get("@timestamp") or db.now()

        if action in ("ssh_login_success", "logon_success") and user:
            net = _net(ev.get("source.ip"))
            seen_nets = self.user_nets.get(user, set())
            seen_hosts = self.user_hosts.get(user, set())
            established = self.user_logins.get(user, 0) >= MIN_USER_LOGINS and self._ready(user, "net")
            new_net = bool(net) and net != "internal" and net not in seen_nets
            new_host = bool(host) and bool(seen_hosts) and host not in seen_hosts
            hour = dt.datetime.fromtimestamp(ts).hour
            off_hours = hour not in BUSINESS_HOURS

            # A login from a never-seen external network is the strong, reliable signal
            # (benign traffic only comes from internal / jump-box addresses).
            if established and new_net and seen_nets:
                alerts.append(self._a("baseline-new-location", "high",
                                      f"{user} logged into {host} from a never-seen network ({net})",
                                      ev, ["T1078"]))
            # A first-time host login on its own is normal for roaming admins, so it is only an alert
            # when it coincides with another anomaly: a new external network or an off-hours login.
            elif established and new_host and (new_net or off_hours):
                why = "from a new network" if new_net else "outside business hours"
                alerts.append(self._a("baseline-new-host-access", "medium",
                                      f"{user} logged into {host} for the first time, {why}", ev, ["T1021"]))

        if action == "process_start" and host:
            procs = self.host_procs.get(host, set())
            name = (ev.get("process.name") or "").lower()
            if procs and len(procs) >= 5 and name and name not in procs:
                sev = "high" if name in ("powershell.exe", "wmic.exe", "mshta.exe", "rundll32.exe",
                                         "cmd.exe", "net.exe", "net1.exe", "schtasks.exe",
                                         "bitsadmin.exe", "psexec.exe") else "low"
                if sev != "low":
                    alerts.append(self._a("baseline-rare-process", sev,
                                          f"rare process {name} first seen on {host}", ev, ["T1059"]))
            hour = dt.datetime.fromtimestamp(ts).hour
            if hour not in BUSINESS_HOURS and name in ("net.exe", "net1.exe", "schtasks.exe", "wmic.exe"):
                alerts.append(self._a("baseline-off-hours-admin", "medium",
                                      f"admin tool {name} run on {host} outside business hours", ev, ["T1059"]))
        return alerts

    def _ready(self, user, _kind):
        return self.total >= MIN_HISTORY

    @staticmethod
    def _a(rule_id, severity, title, ev, mitre):
        return {"id": db.new_id("alr"), "ts": ev.get("@timestamp") or db.now(), "rule_id": rule_id,
                "rule_title": title, "severity": severity, "mitre": mitre, "host": ev.get("host.name"),
                "user": ev.get("user.name"), "src_ip": ev.get("source.ip"),
                "event_ids": [ev.get("_id")], "cves": [], "detector": "baseline"}
