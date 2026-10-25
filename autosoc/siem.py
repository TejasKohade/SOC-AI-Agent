"""SIEM: stores events in SQLite and matches Sigma-style YAML rules (a small field matcher).

Supported Sigma subset: named selections (map = AND of fields, list of maps = OR), list values
(OR), modifiers contains / startswith / endswith / re / gte / lte / exists and `|all`,
conditions with and / or / not / parentheses / `1 of sel*`. Threshold rules use a
`threshold: {count, timeframe, group_by}` block (Sigma correlation, simplified).
"""
import fnmatch
import re
from collections import defaultdict, deque

import yaml

from . import config, db


def load_rules():
    rules = []
    for p in sorted(config.RULES_DIR.glob("*.yml")):
        r = yaml.safe_load(p.read_text())
        r["_file"] = p.name
        rules.append(r)
    return rules


def _match_value(actual, expected, mod):
    if mod == "exists":
        return (actual is not None) == bool(expected)
    if actual is None:
        return False
    if mod in ("gte", "lte"):
        try:
            return float(actual) >= float(expected) if mod == "gte" else float(actual) <= float(expected)
        except (TypeError, ValueError):
            return False
    a, e = str(actual).lower(), str(expected).lower()
    if mod == "contains":
        return e in a
    if mod == "startswith":
        return a.startswith(e)
    if mod == "endswith":
        return a.endswith(e)
    if mod == "re":
        return re.search(str(expected), str(actual), re.I) is not None
    return a == e


def _match_field(event, key, expected):
    field, *mods = key.split("|")
    mod = next((m for m in mods if m != "all"), "")
    want_all = "all" in mods
    values = expected if isinstance(expected, list) else [expected]
    actual = event.get(field)
    results = [_match_value(actual, v, mod) for v in values]
    return all(results) if want_all else any(results)


def _match_selection(event, sel):
    if isinstance(sel, list):
        return any(_match_selection(event, s) for s in sel)
    return all(_match_field(event, k, v) for k, v in sel.items())


_TOKEN = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|\d+ of [\w*]+|all of [\w*]+|[\w]+")


def _eval_condition(cond, hits):
    out = []
    for tok in _TOKEN.findall(cond):
        if tok in ("(", ")", "and", "or", "not"):
            out.append(tok)
        elif " of " in tok:
            q, pat = tok.split(" of ")
            names = [n for n in hits if fnmatch.fnmatch(n, pat)]
            out.append(str(all(hits[n] for n in names) if q == "all" else
                           sum(hits[n] for n in names) >= int(q)))
        else:
            if tok not in hits:
                raise ValueError(f"unknown selection {tok}")
            out.append(str(hits[tok]))
    return eval(" ".join(out), {"__builtins__": {}}, {})  # tokens are only True/False/and/or/not/()


def matches(rule, event):
    det = rule["detection"]
    hits = {k: _match_selection(event, v) for k, v in det.items() if k != "condition"}
    return _eval_condition(det.get("condition", "selection"), hits)


def mitre_of(rule):
    return [t.split(".", 1)[1].upper() for t in rule.get("tags", []) if re.match(r"attack\.t\d", t)]


class RuleEngine:
    def __init__(self, rules=None):
        self.rules = rules if rules is not None else load_rules()
        self.windows = defaultdict(deque)
        self.last_fired = {}

    def process(self, event):
        alerts = []
        for rule in self.rules:
            try:
                if not matches(rule, event):
                    continue
            except Exception:  # malformed events must never break the pipeline
                continue
            th = rule.get("threshold")
            if not th:
                alerts.append(self._alert(rule, event, [event["_id"]]))
                continue
            key = (rule["id"], tuple(event.get(f) for f in th.get("group_by", [])))
            win = self.windows[key]
            win.append((event["@timestamp"], event["_id"]))
            while win and win[0][0] < event["@timestamp"] - th["timeframe"]:
                win.popleft()
            fired = self.last_fired.get(key)
            if len(win) >= th["count"] and (fired is None or event["@timestamp"] - fired > th["timeframe"]):
                self.last_fired[key] = event["@timestamp"]
                alerts.append(self._alert(rule, event, [i for _, i in win][-50:]))
        return alerts

    @staticmethod
    def _alert(rule, event, event_ids):
        cves = re.findall(r"CVE-\d{4}-\d+", str(event.get("vulnerability.id", "")))
        return {
            "id": db.new_id("alr"), "ts": db.now(), "rule_id": rule["id"], "rule_title": rule["title"],
            "severity": rule.get("level", "medium"), "mitre": mitre_of(rule),
            "host": event.get("host.name"), "user": event.get("user.name"),
            "src_ip": event.get("source.ip"), "event_ids": event_ids, "cves": cves,
        }


def store_event(event, run_id):
    from .stream.categorize import categorize
    src_type, category = categorize(event)
    db.insert("events", {
        "id": event["_id"], "ts": event["@timestamp"], "source": event.get("event.module"),
        "host": event.get("host.name"), "user": event.get("user.name"), "action": event.get("event.action"),
        "src_ip": event.get("source.ip"), "dst_ip": event.get("destination.ip"), "raw": event, "run_id": run_id,
        "source_type": src_type, "category": category,
    })


def store_alert(alert, run_id):
    db.insert("alerts", {**alert, "run_id": run_id})
