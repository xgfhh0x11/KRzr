"""Shared fixtures. Adds src/ to sys.path so tests can import the
orchestrator (`client`) without installing anything. Importing it is
safe: the device-opening code lives under `main()`, guarded by
`if __name__ == "__main__"`, so an import never opens the kernel device."""
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)
_SRC = os.path.join(_REPO_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


@pytest.fixture(scope="session")
def repo_root():
    return _REPO_ROOT
