"""APScheduler: runs the VM jobs on their triggers, plus approval escalation, in one process."""
import logging

from apscheduler.schedulers.blocking import BlockingScheduler

from . import soar
from .vm import lifecycle

log = logging.getLogger("autosoc.scheduler")


def build(scheduler=None):
    s = scheduler or BlockingScheduler()
    s.add_job(lifecycle.asset_sync, "interval", hours=1, id="asset_sync")
    s.add_job(lambda: (lifecycle.run_scan(), lifecycle.vm_agent_job(), lifecycle.remediation_job()),
              "interval", days=1, id="scan_cycle")          # jobs 2-7
    s.add_job(lifecycle.verify_job, "interval", minutes=30, id="verify")
    s.add_job(lifecycle.sla_monitor, "interval", hours=1, id="sla_monitor")
    s.add_job(lifecycle.exception_expiry, "interval", days=1, id="exception_expiry")
    s.add_job(lifecycle.weekly_report, "cron", day_of_week="mon", hour=8, id="weekly_report")
    s.add_job(soar.escalate_stale, "interval", minutes=1, id="approval_escalation")
    return s


def main():
    logging.basicConfig(level=logging.INFO)
    s = build()
    log.info("scheduler started with jobs: %s", [j.id for j in s.get_jobs()])
    s.start()
