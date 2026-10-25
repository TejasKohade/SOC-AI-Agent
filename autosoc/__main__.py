"""AutoSOC command line.

  python -m autosoc list                     list scenarios
  python -m autosoc run <id|path> [--approve] replay one scenario (optionally auto-approve tier 2/3)
  python -m autosoc run-all [--approve]       replay every scenario on a fresh database and print metrics
  python -m autosoc vm-cycle                  run VM jobs 1-10 once
  python -m autosoc mocks [--host 0.0.0.0]    serve the mock tool APIs and the live /ingest feed on :8000
  python -m autosoc scheduler                 run the scheduled jobs
  python -m autosoc reset                     wipe runtime state
"""
import argparse
import json
import sys

from . import db, pipeline


def _print_result(r):
    mark = "PASS" if r["passed"] else "FAIL"
    extra = ""
    if "verdicts" in r:
        extra = f"verdict={r['verdicts']} tools={r['tools']} max_tier={r['max_tier']} status={r['statuses']}"
        if r.get("agent_raised"):
            extra += f" agent_raised={r['agent_raised']}"
    else:
        extra = "; ".join(f"{c['expect']}: {c['notes']}" for c in r["checks"] if not c["ok"])
    print(f"[{mark}] {r['scenario']:<26} {r['duration_s']:>6.1f}s  {extra}")
    if not r["passed"] and "checks" in r and isinstance(r["checks"], dict):
        print("        failed checks:", {k: v for k, v in r["checks"].items() if not v})


def summary():
    rows = db.query("SELECT * FROM metrics ORDER BY id")
    soc = [r for r in rows if r["kind"] == "soc"]
    vm = [r for r in rows if r["kind"] == "vm"]
    if soc:
        n = len(soc)
        print(f"\nSOC: {sum(r['passed'] for r in soc)}/{n} passed | detection {sum(r['detected'] for r in soc)}/{n} "
              f"| verdict accuracy {sum(r['verdict_ok'] for r in soc) / n:.0%} "
              f"| right playbook {sum(r['playbook_ok'] for r in soc)}/{n} "
              f"| mean loop {sum(r['duration'] for r in soc) / n:.1f}s")
    if vm:
        print(f"VM:  {sum(r['passed'] for r in vm)}/{len(vm)} scenarios passed")


def main(argv=None):
    p = argparse.ArgumentParser(prog="autosoc")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    r = sub.add_parser("run")
    r.add_argument("scenario")
    r.add_argument("--approve", action="store_true")
    r.add_argument("--fresh", action="store_true", help="wipe state first")
    ra = sub.add_parser("run-all")
    ra.add_argument("--approve", action="store_true")
    ra.add_argument("--kind", choices=["soc", "vm"])
    sub.add_parser("vm-cycle")
    mk = sub.add_parser("mocks")
    mk.add_argument("--host", default="127.0.0.1", help="0.0.0.0 to accept logs from other machines")
    mk.add_argument("--port", type=int, default=8000)
    sub.add_parser("scheduler")
    sub.add_parser("reset")
    sub.add_parser("metrics")
    stp = sub.add_parser("stream", help="continuous mixed-source feed with attacks injected on a timer")
    stp.add_argument("--rate", type=float, default=5.0, help="benign events per second")
    stp.add_argument("--interval", type=float, default=30.0, help="seconds between attack injections")
    stp.add_argument("--duration", type=float, default=0, help="seconds to run (0 = until Ctrl-C)")
    stp.add_argument("--kind", choices=["synthetic", "real"], help="restrict injected attacks")
    stp.add_argument("--fresh", action="store_true")
    a = p.parse_args(argv)

    if a.cmd == "list":
        for s in pipeline.list_scenarios():
            print(f"{s['kind']:<4} {s['id']:<26} {s['description']}")
    elif a.cmd == "run":
        if a.fresh:
            db.wipe()
        res = pipeline.run(a.scenario, auto_approve=a.approve)
        _print_result(res)
        for cid in res.get("cases", []):
            from .agents import orchestrator
            c = orchestrator.get_case(cid)
            print(f"  {cid} [{c['status']}] {c['title']} verdict={c['verdict']} conf={c['confidence']}")
            for act in orchestrator.case_actions(cid):
                print(f"     - {act['tool']} tier={act['tier']} {act['status']} {json.dumps(act['params'])}")
    elif a.cmd == "run-all":
        db.wipe()
        ok = True
        for s in pipeline.list_scenarios(a.kind):
            db.wipe_keep_metrics()
            res = pipeline.run(s["path"], auto_approve=a.approve)
            ok &= res["passed"]
            _print_result(res)
        summary()
        sys.exit(0 if ok else 1)
    elif a.cmd == "metrics":
        summary()
    elif a.cmd == "vm-cycle":
        print(json.dumps(__import__("autosoc.vm.lifecycle", fromlist=["x"]).run_cycle(), indent=2, default=str))
    elif a.cmd == "mocks":
        import uvicorn
        uvicorn.run("autosoc.mocks.app:app", host=a.host, port=a.port)
    elif a.cmd == "scheduler":
        from .scheduler import main as sched
        sched()
    elif a.cmd == "stream":
        from .stream.engine import StreamEngine, scoreboard
        if a.fresh:
            db.wipe()
        eng = StreamEngine(rate=a.rate, interval=a.interval, attack_kind=a.kind)
        print(f"warming up baselines ...")
        eng.warmup()
        print(f"streaming ~{a.rate}/s, attack every {a.interval:.0f}s. Open the dashboard's Live SOC tab. Ctrl-C to stop.")
        import json
        import time as _t
        try:
            if a.duration:
                eng.run_for(a.duration, warmup=False)
            else:
                eng.start()
                last = 0
                while True:
                    _t.sleep(5)
                    s = eng.stats
                    if s["attacks"] != last:
                        last = s["attacks"]
                        sb = scoreboard()
                        print(f"  events {s['events']:>5} | attacks {s['attacks']:>3} | cases {s['cases']:>3} | "
                              f"detected {sb['detected']}/{sb['injected']}")
        except KeyboardInterrupt:
            eng.stop()
            print("\n--- scoreboard ---")
            print(json.dumps(scoreboard(), indent=2))
    elif a.cmd == "reset":
        db.wipe()
        print("state wiped")


if __name__ == "__main__":
    main()
