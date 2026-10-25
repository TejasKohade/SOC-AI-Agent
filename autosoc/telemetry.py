"""Telemetry generator: replays a scenario file as ECS-style JSON events mixed with benign noise."""
import base64
import random

import yaml
from faker import Faker

from . import db

ALIASES = {
    "source": "event.module", "action": "event.action", "host": "host.name", "user": "user.name",
    "src_ip": "source.ip", "dst_ip": "destination.ip", "process": "process.name",
    "cmd": "process.command_line", "parent": "process.parent.name", "hash": "file.hash.sha256",
    "url": "url.full", "domain": "url.domain", "bytes": "network.bytes", "cve": "vulnerability.id",
    "event_id": "winlog.event_id", "target": "process.target.name",
}


def _parse_dur(v):
    if v is None:
        return 1.0
    if isinstance(v, (int, float)):
        return float(v)
    unit = v[-1]
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(unit)
    return float(v[:-1]) * mult if mult else float(v)


def normalise(raw):
    ev = {}
    for k, v in raw.items():
        ev[ALIASES.get(k, k)] = v
    if "encode_cmd" in ev:  # helper: build a PowerShell -EncodedCommand from plain text
        enc = base64.b64encode(ev.pop("encode_cmd").encode("utf-16-le")).decode()
        ev["process.command_line"] = f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {enc}"
    ev.setdefault("ecs.version", "8.11")
    return ev


# Who normally logs in where, and from which admin/jump hosts: benign noise must look like a real
# environment, or the agents (correctly) flag the noise itself as lateral movement.
USUAL_LOGINS = {
    "web-01": (["deploy", "carol"], ["10.0.5.10", "10.0.5.11"]),   # CI runner, jump host
    "app-02": (["carol", "bob"], ["10.0.5.11"]),
    "db-01": (["carol"], ["10.0.5.11"]),
    "srv-win-04": (["carol"], ["10.0.5.11"]),
    "mail-gw": (["carol"], ["10.0.5.11"]),
}


def _noise(spec, hosts, t0, span, fake):
    out = []
    users = ["alice", "bob", "carol"]
    for _ in range(spec.get("benign_logins", 0)):
        h = random.choice(hosts)
        if h.startswith("wks-"):
            owner = {"wks-alice-01": "alice", "wks-bob-02": "bob", "wks-carol-03": "carol"}.get(h, "alice")
            out.append({"event.module": "windows", "event.action": "logon_success", "host.name": h,
                        "user.name": owner, "source.ip": "127.0.0.1"})
            continue
        who, src = USUAL_LOGINS.get(h, (["carol"], ["10.0.5.11"]))
        out.append({"event.module": "auditd", "event.action": "ssh_login_success", "host.name": h,
                    "user.name": random.choice(who), "source.ip": random.choice(src)})
    for _ in range(spec.get("benign_processes", 0)):
        p = random.choice(["chrome.exe", "outlook.exe", "teams.exe", "excel.exe", "svchost.exe"])
        out.append({"event.module": "sysmon", "event.action": "process_start", "winlog.event_id": 1,
                    "host.name": random.choice([h for h in hosts if h.startswith("wks")] or hosts),
                    "user.name": random.choice(users), "process.name": p,
                    "process.command_line": f"C:\\Program Files\\{p}", "process.parent.name": "explorer.exe"})
    for _ in range(spec.get("benign_dns", 0)):
        out.append({"event.module": "dns", "event.action": "dns_query", "host.name": random.choice(hosts),
                    "url.domain": fake.domain_name(), "destination.ip": "10.0.0.53"})
    for _ in range(spec.get("benign_emails", 0)):
        out.append({"event.module": "email", "event.action": "email_delivered", "host.name": "mail-gw",
                    "email.from": fake.company_email(), "email.to": random.choice(users) + "@corp.local",
                    "email.subject": fake.sentence(nb_words=5), "url.full": fake.url(),
                    "email.message_id": f"<{fake.uuid4()}@mail>"})
    for _ in range(spec.get("malformed", 0)):
        out.append(random.choice([{"event.module": "unknown"}, {"host.name": None, "event.action": 42},
                                  {"process.command_line": "\x00\x01garbage", "event.module": "sysmon"}]))
    for ev in out:
        ev["@timestamp"] = t0 + random.uniform(0, span)
    return out


def generate(scenario, seed=7):
    """Return the scenario's events in time order, ending just before 'now'."""
    random.seed(seed)
    fake = Faker()
    Faker.seed(seed)
    attack, t = [], 0.0
    for step in scenario.get("events", []):
        t += _parse_dur(step.get("after", 0))
        for _ in range(int(step.get("repeat", 1))):
            attack.append((t, normalise(step["event"])))
            t += _parse_dur(step.get("every", "1s"))
    span = max(t, 60.0)
    t0 = db.now() - span - 5
    events = []
    for off, ev in attack:
        ev = dict(ev)
        ev["@timestamp"] = t0 + off
        events.append(ev)
    hosts = scenario.get("noise_hosts") or ["web-01", "app-02", "db-01", "wks-alice-01", "wks-bob-02"]
    events += _noise(scenario.get("noise", {}), hosts, t0, span, fake)
    events.sort(key=lambda e: e["@timestamp"])
    for ev in events:
        ev["_id"] = db.new_id("evt")
    return events


def load_scenario(path):
    return yaml.safe_load(open(path))
