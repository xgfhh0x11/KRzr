"""Orchestrator checks — the user-mode `client.py` is the only part of
KRzr testable without a privileged kernel VM. These tests import it
(safe: device I/O is under the `__main__` guard) and assert the pieces
the driver contract depends on. This satisfies the BUILD_AND_VERIFY
"what could run today without a kernel VM" gap.

The import requires `ctypes.wintypes`, so these tests run on Windows
(where CI for this Windows-kernel project runs); they skip elsewhere."""
import sys

import pytest

if sys.platform != "win32":
    pytest.skip("client.py imports ctypes.wintypes — Windows only", allow_module_level=True)

import client  # noqa: E402  (path injected by conftest)


def test_module_compiles_and_imports():
    assert client is not None


def test_fuzzing_config_defaults():
    cfg = client.FuzzingConfig()
    assert cfg.max_iterations == 1000
    assert cfg.max_threads == 10
    assert cfg.max_resources == 100
    assert cfg.timeout_ms == 30000
    assert cfg.crash_threshold == 10
    assert cfg.pattern_threshold == 1
    assert cfg.enable_coverage is True
    assert cfg.enable_fault_patterns is True


@pytest.mark.parametrize(
    "name,value",
    [
        ("IOCTL_START_FUZZING", 0x80002000),
        ("IOCTL_STOP_FUZZING", 0x80002004),
        ("IOCTL_GET_STATUS", 0x80002008),
        ("IOCTL_SIMULATE_RACE", 0x8000201C),
        ("IOCTL_GET_COVERAGE", 0x80002020),
        ("IOCTL_GET_FAULT_PATTERNS", 0x80002024),
    ],
)
def test_ioctl_codes_match_driver_contract(name, value):
    """These must stay in lockstep with the kernel driver's IOCTL codes;
    a silent drift here is the classic user/kernel mismatch bug."""
    assert getattr(client, name) == value


def test_client_class_is_a_context_manager():
    assert hasattr(client, "KernelFuzzerClient")
    cls = client.KernelFuzzerClient
    assert hasattr(cls, "__enter__") and hasattr(cls, "__exit__")
