"""IOCTL round-trip tests for client.py with DeviceIoControl mocked.

The driver needs a privileged kernel VM, but the *packing* of the
config struct sent to the driver and the *unpacking* of the status
struct returned by it are pure user-mode logic — and exactly the place
a user/kernel struct-layout drift would hide. These tests replace
`kernel32.DeviceIoControl` with a fake that captures the input buffer
and supplies a crafted output buffer, then assert the round-trip.

Windows-only (client.py imports ctypes.wintypes); skips elsewhere."""
import struct
import sys

import pytest

if sys.platform != "win32":
    pytest.skip("client.py imports ctypes.wintypes — Windows only", allow_module_level=True)

import client  # noqa: E402  (path injected by conftest)


class _FakeKernel32:
    """Stand-in for ctypes.windll.kernel32 capturing DeviceIoControl."""

    def __init__(self, status_payload=None):
        self.calls = []
        self.status_payload = status_payload

    def DeviceIoControl(self, handle, ioctl, in_buf, in_len,
                        out_buf, out_len, bytes_ret, overlapped):
        self.calls.append({"ioctl": ioctl, "in_buf": in_buf, "in_len": in_len,
                           "out_len": out_len})
        if out_buf is not None and self.status_payload is not None:
            out_buf[:len(self.status_payload)] = self.status_payload
            bytes_ret._obj.value = len(self.status_payload)  # write through byref
        return 1  # non-zero == success


def _client(fake):
    c = client.KernelFuzzerClient()
    c.driver_handle = 1            # bypass connect(); any truthy handle
    c.kernel32 = fake
    return c


def test_start_fuzzing_packs_config_as_eight_ulongs():
    fake = _FakeKernel32()
    c = _client(fake)
    cfg = client.FuzzingConfig(
        max_iterations=123, max_threads=4, max_resources=50,
        timeout_ms=9000, crash_threshold=7, pattern_threshold=2,
        enable_coverage=True, enable_fault_patterns=False,
    )
    assert c.start_fuzzing(cfg) is True
    call = fake.calls[-1]
    assert call["ioctl"] == client.IOCTL_START_FUZZING
    assert call["in_len"] == 32  # 8 × ULONG
    vals = struct.unpack("IIIIIIII", bytes(call["in_buf"]))
    assert vals == (123, 4, 50, 9000, 7, 2, 1, 0)


def test_get_status_unpacks_nine_ulongs_into_fields():
    payload = struct.pack("IIIIIIIII", 1, 100, 2, 3, 4, 55, 6, 7, 8)
    fake = _FakeKernel32(status_payload=payload)
    c = _client(fake)
    st = c.get_status()
    assert st is not None
    assert st.is_running is True
    assert st.iterations_completed == 100
    assert st.crashes_found == 2
    assert st.patterns_found == 3
    assert st.race_conditions_detected == 4
    assert st.coverage_percentage == 55
    assert st.unique_paths == 6
    assert st.total_threads_created == 7
    assert st.total_resources_created == 8
    assert fake.calls[-1]["ioctl"] == client.IOCTL_GET_STATUS


def test_stop_fuzzing_issues_stop_ioctl_with_no_payload():
    fake = _FakeKernel32()
    c = _client(fake)
    assert c.stop_fuzzing() is True
    call = fake.calls[-1]
    assert call["ioctl"] == client.IOCTL_STOP_FUZZING
    assert call["in_buf"] is None and call["in_len"] == 0
