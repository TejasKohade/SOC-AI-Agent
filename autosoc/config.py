import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DATA_DIR = ROOT / "data"
DB_PATH = Path(os.getenv("AUTOSOC_DB", DATA_DIR / "autosoc.db"))
SCENARIO_DIR = ROOT / "scenarios"
RULES_DIR = ROOT / "siem" / "rules"
PLAYBOOK_DIR = ROOT / "playbooks"
INVENTORY_DIR = ROOT / "inventory"
INTEL_DIR = ROOT / "intel"
VULN_DIR = ROOT / "vulns"
TUNING_DIR = ROOT / "tuning"

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "bedrock").lower()
MOCK_BASE_URL = os.getenv("MOCK_BASE_URL", "").strip()

# Per-alert budgets (keeps us inside free-tier caps)
MAX_TOOL_CALLS_PER_ALERT = 20
MAX_LLM_CALLS_PER_ALERT = 5

# Dedupe window: alerts on the same host/user within this many seconds join one case
DEDUPE_WINDOW_S = 15 * 60
# Tier 2 approvals escalate if unanswered for this long
APPROVAL_ESCALATE_S = 15 * 60
# Raise tier when confidence is below this
CONFIDENCE_FLOOR = 0.80
