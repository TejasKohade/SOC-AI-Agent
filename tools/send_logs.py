"""Stream logs to the AutoSOC /ingest endpoint as a live feed (stands in for Vector / Fluent Bit / Wazuh).

  python tools/send_logs.py scenarios/soc/01_ssh_bruteforce.yml          scenario events, real-time pacing
  python tools/send_logs.py scenarios/soc/01_ssh_bruteforce.yml --speed 5 five times faster
  python tools/send_logs.py /var/log/auth.log                            raw syslog lines -> /ingest/syslog
  python tools/send_logs.py events.jsonl                                 one ECS JSON event per line -> /ingest

Scenario files are expanded with the same generator the replay uses (attack + benign noise + malformed
events). Event timestamps are left to the server, so the feed looks like it is happening now. Syslog
lines are paced by their own timestamps (or --interval when they have none) and re-stamped with the
current time unless --keep-time is given.
"""
import argparse
import datetime as dt
import json
import re
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_BSD_TS = re.compile(r"^(<\d+>)?([A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d)")


def scenario_items(path):
    from autosoc import telemetry
    events = telemetry.generate(telemetry.load_scenario(path))
    t0 = events[0]["@timestamp"] if events else 0
    out = []
    for e in events:
        off = e["@timestamp"] - t0
        out.append((off, {k: v for k, v in e.items() if k not in ("@timestamp", "_id")}))
    return out


def syslog_items(path, interval):
    out, first = [], None
    for i, line in enumerate(l for l in Path(path).read_text(errors="replace").splitlines() if l.strip()):
        m = _BSD_TS.match(line)
        off = i * interval
        if m:
            try:
                t = dt.datetime.strptime(f"2000 {m[2]}", "%Y %b %d %H:%M:%S").timestamp()
                first = t if first is None else first
                off = t - first
            except ValueError:
                pass
        out.append((off, line))
    return out


def jsonl_items(path, interval):
    return [(i * interval, json.loads(l)) for i, l in enumerate(Path(path).read_text().splitlines()) if l.strip()]


def retime(line):
    now = dt.datetime.now().strftime("%b %d %H:%M:%S")
    return _BSD_TS.sub(lambda m: (m[1] or "") + now, line, count=1)


def send(client, kind, batch, keep_time):
    if kind == "syslog":
        body = "\n".join(l if keep_time else retime(l) for l in batch)
        r = client.post("/ingest/syslog", content=body, headers={"content-type": "text/plain"})
    else:
        r = client.post("/ingest", json=batch)
    r.raise_for_status()
    return r.json()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("path", help="scenario .yml, raw syslog file, or .jsonl of ECS events")
    p.add_argument("--url", default="http://127.0.0.1:8000")
    p.add_argument("--speed", type=float, default=1.0, help="time compression factor (1 = real time)")
    p.add_argument("--interval", type=float, default=0.5, help="seconds between lines with no timestamp")
    p.add_argument("--keep-time", action="store_true", help="send syslog lines with their original timestamps")
    p.add_argument("--no-wait", action="store_true", help="exit as soon as the last event is sent")
    a = p.parse_args(argv)

    path = Path(a.path)
    if path.suffix in (".yml", ".yaml"):
        kind, items = "json", scenario_items(path)
    elif path.suffix in (".jsonl", ".ndjson", ".json"):
        kind, items = "json", jsonl_items(path, a.interval)
    else:
        kind, items = "syslog", syslog_items(path, a.interval)
    span = items[-1][0] / a.speed if items else 0
    print(f"streaming {len(items)} events from {path.name} to {a.url} over ~{span:.0f}s (speed x{a.speed:g})")

    client = httpx.Client(base_url=a.url, timeout=30)
    start, i, sent, alerts = time.time(), 0, 0, 0
    while i < len(items):
        now = time.time() - start
        batch = []
        while i < len(items) and items[i][0] / a.speed <= now:
            batch.append(items[i][1])
            i += 1
        if batch:
            res = send(client, kind, batch, a.keep_time)
            sent += res["accepted"]
            alerts += len(res["alerts"])
            mark = f"  ALERT x{len(res['alerts'])}" if res["alerts"] else ""
            print(f"\r[{now:6.1f}s] sent {sent}/{len(items)} events, {alerts} alerts{mark}",
                  end="\n" if mark else "", flush=True)
        if i < len(items):
            time.sleep(min(0.25, max(0.0, items[i][0] / a.speed - (time.time() - start))))
    print()
    if a.no_wait:
        return
    print("waiting for the agents to finish ...")
    while True:
        st = client.get("/ingest/status").json()
        if not st["pending_alerts"] and not st["in_flight"]:
            break
        time.sleep(2)
    for c in st["cases"]:
        print(f"  {c['id']} [{c['status']}] {c['title']} verdict={c['verdict']}")


if __name__ == "__main__":
    main()
