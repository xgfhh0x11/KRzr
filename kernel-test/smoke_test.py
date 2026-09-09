"""
KRzr smoke test  -  drives the driver's real IOCTLs the same way src/client.py
does, using client.py's own KernelFuzzerClient rather than reimplementing
DeviceIoControl. Scoped to the four IOCTLs that are actually wired behind
real kernel logic today (see ../README.md / BUILD_AND_VERIFY.md Section 3.3):

    IOCTL_ALLOCATE_MEMORY, IOCTL_FREE_MEMORY,
    IOCTL_GET_COVERAGE, IOCTL_GET_FAULT_PATTERNS

Deliberately does NOT call IOCTL_START_FUZZING / IOCTL_SIMULATE_RACE /
IOCTL_CREATE_THREAD here: START_FUZZING launches the real fuzzing loop
(the documented use-after-return / unload-race surface), CREATE_THREAD
spins up a kernel system thread, and this is meant to be a low-risk sanity
check of the IOCTL contract, not a fuzzing run. Use client.py directly (or
a dedicated harness) once you deliberately want to exercise those paths,
with a checkpoint taken first regardless.

Runs INSIDE the guest, against a driver that is already loaded (see
load.ps1). Never invoked directly by anything on the host; smoke-test.ps1
is the -Arm-gated wrapper that calls this.

Exit code: 0 all checks passed, 1 any check failed or driver unreachable.
"""

import os
import sys

# src/client.py is the real orchestrator; import it directly rather than
# duplicating its DeviceIoControl plumbing or struct layouts.
_SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
sys.path.insert(0, _SRC_DIR)

try:
    from client import KernelFuzzerClient  # noqa: E402
except ImportError as exc:
    print(f"FAIL: could not import client.py from {_SRC_DIR}: {exc}")
    sys.exit(1)


PASS = []
FAIL = []


def check(name, condition, detail=""):
    if condition:
        PASS.append(name)
        print(f"  PASS  {name}" + (f" ({detail})" if detail else ""))
    else:
        FAIL.append(name)
        print(f"  FAIL  {name}" + (f" ({detail})" if detail else ""))


def main():
    print("=== KRzr smoke test (allocate/free/coverage/fault-patterns) ===")
    print(f"Importing client from: {_SRC_DIR}")
    print()

    with KernelFuzzerClient() as client:
        check("connect", bool(client.driver_handle), "opened \\\\.\\KernelFuzzer")
        if not client.driver_handle:
            print()
            print("Cannot reach the driver  -  is the KernelFuzzer service RUNNING?")
            print("(sc query KernelFuzzer should report STATE: 4 RUNNING)")
            return summarize()

        # --- IOCTL_ALLOCATE_MEMORY / IOCTL_FREE_MEMORY ---------------------
        alloc_size = 4096
        address = client.allocate_memory(alloc_size)
        check(
            "allocate_memory(4096) returns a non-null pointer",
            address is not None and address != 0,
            f"address=0x{address:x}" if address else "address=None",
        )

        if address:
            freed = client.free_memory(address)
            check("free_memory(returned address) succeeds", freed is True)

        # Kernel-side rejects 0 and > 1 MiB (kernel_fuzzer.c IOCTL_ALLOCATE_MEMORY
        # case); confirm the client surfaces that as a clean failure, not a crash.
        zero_alloc = client.allocate_memory(0)
        check(
            "allocate_memory(0) is rejected (kernel validates allocSize)",
            zero_alloc is None,
            f"got {zero_alloc!r}" if zero_alloc is not None else "",
        )

        huge_alloc = client.allocate_memory(2 * 1024 * 1024)  # > 1 MiB cap
        check(
            "allocate_memory(2 MiB) is rejected (over the 1 MiB kernel cap)",
            huge_alloc is None,
            f"got {huge_alloc!r}" if huge_alloc is not None else "",
        )

        # free_memory on an obviously-bogus address should fail cleanly
        # (IsAddressValid rejects NULL / < 0x1000), not corrupt anything.
        bogus_free = client.free_memory(0x10)
        check(
            "free_memory(0x10) is rejected (IsAddressValid guard)",
            bogus_free is False,
        )

        # --- IOCTL_GET_COVERAGE ---------------------------------------------
        coverage = client.get_coverage_stats()
        cov_ok = False
        if isinstance(coverage, dict) and set(coverage) == {"total_points", "hit_points", "percentage"}:
            vals_ok = all(isinstance(v, int) and v >= 0 for v in coverage.values())
            cov_ok = (
                vals_ok
                and coverage["hit_points"] <= coverage["total_points"]
                and 0 <= coverage["percentage"] <= 100
            )
        check(
            "get_coverage_stats() returns a well-formed record",
            cov_ok,
            repr(coverage),
        )

        # --- IOCTL_GET_FAULT_PATTERNS ---------------------------------------
        patterns = client.get_fault_pattern_stats()
        pat_ok = False
        if isinstance(patterns, dict) and set(patterns) == {"total_patterns", "high_confidence_patterns"}:
            pat_ok = all(isinstance(v, int) and v >= 0 for v in patterns.values())
        check(
            "get_fault_pattern_stats() returns a well-formed record",
            pat_ok,
            repr(patterns),
        )

    return summarize()


def summarize():
    print()
    print(f"=== {len(PASS)} passed, {len(FAIL)} failed ===")
    if FAIL:
        print("Failed checks:")
        for name in FAIL:
            print(f"  - {name}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
