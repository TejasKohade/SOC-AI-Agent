"""Asset / identity inventory (mock CMDB + Entra ID) and the CVE catalogue snapshot."""
import copy
import json
from functools import lru_cache

from . import config, db


@lru_cache
def _hosts_file():
    return json.loads((config.INVENTORY_DIR / "hosts.json").read_text())["hosts"]


@lru_cache
def users():
    return {u["name"]: u for u in json.loads((config.INVENTORY_DIR / "users.json").read_text())["users"]}


def hosts():
    """Live host records: the inventory file overlaid with mutable state (patch levels)."""
    out = {}
    for h in _hosts_file():
        row = db.one("SELECT data FROM hosts_state WHERE host=?", (h["name"],))
        out[h["name"]] = db.loads(row["data"]) if row else copy.deepcopy(h)
    return out


def host(name):
    return hosts().get(name)


def user(name):
    return users().get(name)


def save_host(h):
    db.insert("hosts_state", {"host": h["name"], "data": h})


@lru_cache
def _catalogue_file():
    return json.loads((config.VULN_DIR / "catalogue.json").read_text())["vulnerabilities"]


def catalogue():
    """CVE snapshot with runtime KEV additions (the 'new KEV entry' feed)."""
    extra_kev = set(db.loads((db.one("SELECT v FROM kv WHERE k='kev_additions'") or {}).get("v"), []))
    out = {}
    for v in _catalogue_file():
        v = dict(v)
        if v["cve"] in extra_kev:
            v["kev"] = True
        out[v["cve"]] = v
    return out


def add_kev(cve):
    cur = set(db.loads((db.one("SELECT v FROM kv WHERE k='kev_additions'") or {}).get("v"), []))
    cur.add(cve)
    db.execute("INSERT OR REPLACE INTO kv (k, v) VALUES ('kev_additions', ?)", (json.dumps(sorted(cur)),))
