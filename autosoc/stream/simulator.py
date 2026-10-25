"""Continuous event stream: one mixed feed of normal activity with attacks injected at random.

Unlike a scenario replay (one attack, known answer, played alone), this runs until stopped and mixes
many sources. Normal activity is generated per host/user from a routine; every INTERVAL seconds one
attack is injected, chosen at random from:
  - synthetic techniques (brute force, phishing, encoded PowerShell, impossible-travel login, exfil)
  - REAL OTRF captures (Mimikatz, LSASS dump, scheduled-task persistence, WMIC backdoor, PsExec, ...)

Attacks land on a random asset/user from our inventory. Everything the simulator injects is written
to a hidden ground-truth log (the `injections` table) so the scoreboard can grade detection later;
the detection side never reads it.
"""
import random
import time

from faker import Faker

from .. import db, inventory
from . import otrf

fake = Faker()

BENIGN_USERS = ["alice", "bob", "carol", "deploy"]
WORKSTATIONS = {"wks-alice-01": "alice", "wks-bob-02": "bob", "wks-carol-03": "carol"}
LINUX_SERVERS = ["web-01", "app-02", "db-01"]
WIN_SERVERS = ["srv-win-04", "dc-01"]
ADMIN_JUMP = ["10.0.5.10", "10.0.5.11"]
BENIGN_PROCS = ["chrome.exe", "outlook.exe", "teams.exe", "excel.exe", "code.exe", "svchost.exe"]
BENIGN_DOMAINS = ["update.microsoft.com", "github.com", "slack.com", "google.com", "office.com"]


# ---------------- normal activity ----------------

def _benign_event():
    kind = random.choices(["login", "process", "dns", "email"], weights=[3, 4, 2, 1])[0]
    if kind == "login":
        host = random.choice(LINUX_SERVERS + list(WORKSTATIONS))
        if host in WORKSTATIONS:
            return {"event.module": "windows", "event.action": "logon_success", "host.name": host,
                    "user.name": WORKSTATIONS[host], "source.ip": "127.0.0.1"}
        return {"event.module": "auditd", "event.action": "ssh_login_success", "host.name": host,
                "user.name": random.choice(["deploy", "carol"]), "source.ip": random.choice(ADMIN_JUMP)}
    if kind == "process":
        host = random.choice(list(WORKSTATIONS))
        p = random.choice(BENIGN_PROCS)
        return {"event.module": "sysmon", "event.action": "process_start", "winlog.event_id": 1,
                "host.name": host, "user.name": WORKSTATIONS[host], "process.name": p,
                "process.command_line": f"C:\\Program Files\\{p}", "process.parent.name": "explorer.exe"}
    if kind == "dns":
        host = random.choice(LINUX_SERVERS + list(WORKSTATIONS))
        return {"event.module": "dns", "event.action": "dns_query", "host.name": host,
                "url.domain": random.choice(BENIGN_DOMAINS), "destination.ip": "10.0.0.53"}
    return {"event.module": "email", "event.action": "email_delivered", "host.name": "mail-gw",
            "email.from": fake.company_email(), "email.to": random.choice(BENIGN_USERS) + "@corp.local",
            "email.subject": fake.sentence(nb_words=5), "url.full": f"https://{random.choice(BENIGN_DOMAINS)}/x",
            "email.message_id": f"<{fake.uuid4()}@mail>"}


# ---------------- synthetic attacks ----------------

def _pick_target(os_kind=None):
    hosts = [h for h in inventory.hosts().values()
             if os_kind is None or h["os"] == os_kind]
    return random.choice(hosts)


def _syn_bruteforce():
    h = random.choice([inventory.host(x) for x in LINUX_SERVERS])
    ip = fake.ipv4_public()
    user = random.choice(["root", "deploy", "admin"])
    evs = [{"event.module": "auditd", "event.action": "ssh_login_failed", "host.name": h["name"],
            "user.name": user, "source.ip": ip} for _ in range(random.randint(12, 25))]
    evs.append({"event.module": "auditd", "event.action": "ssh_login_success", "host.name": h["name"],
                "user.name": user, "source.ip": ip})
    return evs, {"mitre": "T1110", "label": f"SSH brute force on {h['name']}", "host": h["name"],
                 "user": user, "indicator": ip}


def _syn_phishing():
    victims = random.sample(BENIGN_USERS, 2)
    dom = "login-micros0ft.test"
    evs = [{"event.module": "email", "event.action": "email_delivered", "host.name": "mail-gw",
            "email.from": f"it-support@{dom}", "email.to": f"{v}@corp.local",
            "email.subject": "Action required: password reset", "url.full": f"http://{dom}/reset",
            "url.domain": dom, "email.message_id": f"<ph-{fake.uuid4()}@mail>"} for v in victims]
    return evs, {"mitre": "T1566", "label": "Phishing campaign (look-alike domain)", "host": "mail-gw",
                 "user": victims[0], "indicator": dom}


def _syn_encoded_ps():
    host, user = random.choice(list(WORKSTATIONS.items()))
    ip = "198.51.100.23"
    evs = [{"event.module": "sysmon", "event.action": "process_start", "winlog.event_id": 1,
            "host.name": host, "user.name": user, "process.name": "powershell.exe",
            "process.parent.name": "winword.exe",
            "process.command_line": f"powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ== # downloads from {ip}"},
           {"event.module": "sysmon", "event.action": "network_connection", "winlog.event_id": 3,
            "host.name": host, "user.name": user, "process.name": "powershell.exe", "destination.ip": ip}]
    return evs, {"mitre": "T1059.001", "label": f"Encoded PowerShell cradle on {host}", "host": host,
                 "user": user, "indicator": ip}


def _syn_impossible_travel():
    user = random.choice(BENIGN_USERS)
    host = "web-01"
    evs = [{"event.module": "auditd", "event.action": "ssh_login_success", "host.name": host,
            "user.name": user, "source.ip": "203.0.113.45"},
           {"event.module": "windows", "event.action": "logon_success", "host.name": host,
            "user.name": user, "source.ip": "198.51.100.23"}]
    return evs, {"mitre": "T1078", "label": f"Impossible-travel login for {user}", "host": host,
                 "user": user, "indicator": "203.0.113.45"}


def _syn_exfil():
    h = random.choice([inventory.host(x) for x in LINUX_SERVERS])
    dst = fake.ipv4_public()
    evs = [{"event.module": "firewall", "event.action": "network_flow", "network.direction": "outbound",
            "host.name": h["name"], "destination.ip": dst, "network.bytes": random.randint(600, 980) * 1_000_000}]
    return evs, {"mitre": "T1048", "label": f"Large outbound transfer from {h['name']}", "host": h["name"],
                 "user": None, "indicator": dst}


SYNTHETIC = [_syn_bruteforce, _syn_phishing, _syn_encoded_ps, _syn_impossible_travel, _syn_exfil]


# ---------------- real attacks (OTRF) ----------------

def _real_attack(name):
    h = _pick_target("windows")
    user = random.choice(["bob", "carol"])
    evs, meta = otrf.load(name, h["name"], user)
    return evs, {"mitre": meta["mitre"], "label": f"{meta['label']} on {h['name']}", "host": h["name"],
                 "user": user, "indicator": None, "source": meta["source"], "technique": name}


def attack_catalogue():
    real = [("real", n) for n in otrf.available()]
    syn = [("synthetic", f.__name__) for f in SYNTHETIC]
    return syn + real


def make_specific(technique):
    """Inject one named attack: a synthetic function name or an OTRF technique folder."""
    fn = next((f for f in SYNTHETIC if f.__name__ == technique), None)
    if fn:
        evs, meta = fn()
        meta["origin"] = "synthetic"
        return evs, meta
    evs, meta = _real_attack(technique)
    meta["origin"] = "real"
    return evs, meta


def make_attack(kind=None):
    """Return (events, meta). kind: 'synthetic' | 'real' | None (random)."""
    choices = attack_catalogue()
    if kind:
        choices = [c for c in choices if c[0] == kind]
    origin, which = random.choice(choices)
    if origin == "synthetic":
        fn = next(f for f in SYNTHETIC if f.__name__ == which)
        evs, meta = fn()
    else:
        evs, meta = _real_attack(which)
    meta["origin"] = origin
    return evs, meta


# ---------------- ground truth ----------------

def record_injection(meta, event_ids, at):
    iid = db.new_id("inj")
    db.insert("injections", {"id": iid, "ts": at, "origin": meta["origin"], "mitre": meta.get("mitre"),
                             "label": meta["label"], "host": meta.get("host"), "user": meta.get("user"),
                             "indicator": meta.get("indicator"), "event_ids": event_ids,
                             "source": meta.get("source", "synthetic"), "matched_case": None, "detected": 0})
    return iid
