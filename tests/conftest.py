import os
import tempfile

# Tests are deterministic: offline LLM stand-in and a throwaway database.
os.environ["LLM_PROVIDER"] = "offline"
os.environ["AUTOSOC_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

import pytest  # noqa: E402

from autosoc import db  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_state():
    db.wipe()
    yield
