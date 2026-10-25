"""Replay every scenario and assert its expected outcome (detection-as-code)."""
import pytest

from autosoc import pipeline
from autosoc.agents import orchestrator

SOC = pipeline.list_scenarios("soc")
VM = pipeline.list_scenarios("vm")


@pytest.mark.parametrize("sc", SOC, ids=[s["id"] for s in SOC])
def test_soc_scenario(sc):
    r = pipeline.run(sc["path"])
    assert r["passed"], r["checks"]


@pytest.mark.parametrize("sc", VM, ids=[s["id"] for s in VM])
def test_vm_scenario(sc):
    r = pipeline.run(sc["path"])
    failed = [c for c in r["checks"] if not c["ok"]]
    assert r["passed"], failed


@pytest.mark.parametrize("sid", ["ssh-bruteforce-01", "encoded-powershell-01", "schtask-persistence-01"])
def test_approval_closes_the_loop(sid):
    r = pipeline.run(sid, auto_approve=True)
    for cid in r["cases"]:
        c = orchestrator.get_case(cid)
        assert c["status"] == "closed", (cid, c["status"])
        assert c["report"]["verification"]["all_verified"]
        assert c["report"]["final"]["report_markdown"]
