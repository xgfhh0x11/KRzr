# KRzr — Kernel Race Condition Detector

A Windows kernel-mode fuzzer for surfacing race conditions in kernel
code paths: synchronization mistakes, lock-bypass windows, TOCTOU
sequences, and concurrency-sensitive use-after-free / double-free
patterns.

The implementation is a single-file WDM kernel driver paired with a
Python client. The source defines five module-shaped groups of
functions; **only a thin slice of that surface is actually wired into
the running fuzzing loop** (see "What actually runs" below). The client
drives campaigns and polls status/coverage/pattern IOCTLs.

---

## Modules (as designed — see "What actually runs" for what is wired)

1. **Thread Interleaving Simulator.** Creates kernel system threads
   (`PsCreateSystemThread`), assigns CPU affinity / priority, and
   injects controlled jitter (`KeDelayExecutionThread` with random
   offsets) so that paired threads visit shared state in adversarial
   orderings.
2. **Shared Resource Mutator.** Targets kernel objects exercised by
   concurrent paths: kernel pool allocations, file handles, registry
   keys, named pipes, section objects, mutexes, events, semaphores.
3. **Race Detector.** Lockset analysis maintained per-thread; flags
   shared accesses without consistent lock coverage and pairs of
   accesses with a lock-bypass interleaving.
4. **Fault Pattern Generator.** When the detector flags a race window,
   the pattern generator emits a structured fault-pattern record
   describing the candidate bug class (UAF / double-free / heap-spray
   neighbourhood / ROP-chain neighbourhood / privilege-context delta
   / code-injection candidate). The record is a *classification*, not
   a weaponised payload.
5. **Coverage Tracker.** Maintains an instruction-coverage bitmap; the
   source also defines a mutation/feedback engine intended to bias
   future trials toward unexplored code paths.

## What actually runs

`FuzzingIteration()` (the body of the per-iteration loop) only exercises:
`GenerateInput` (allocates a random buffer, never consumed), 
`CreateFuzzingResources`/`CreateFuzzingThreads` (module 1/2 object
creation), `UpdateCoverage` (a synthetic address, not real
instrumentation), `DetectRaceConditions`, `SynthesizeFaultPatterns`,
`UpdateStatistics`. The one detector that genuinely runs is the lockset
path: `ThreadWorker → SimulateThreadRace → RecordMemoryAccess` /
`RecordLockAcquisition`, feeding **fixed synthetic addresses**, not real
kernel state. Fault synthesis is hard-wired to
`FAULT_PATTERN_USE_AFTER_FREE` — the other five `FaultPatternType`
classes are defined but never emitted by a running campaign.

**Defined but never called from any live path** (compiles, but does not
run): the shadow-table memory-safety detectors (`DetectUseAfterFree`,
`DetectDoubleFree`, `DetectUninitializedMemory`, `DetectBufferOverflow`,
`DetectNullPointerDeref`, `DetectIntegerOverflow` — their shadow table is
never populated because `ShadowMark` is never called); `AnalyzeLockset`;
the Module-5 mutation/feedback engine (`AddInput`, `GetNextInput`,
`MutateInput` and its `BitFlip…HavocMutation` mutators,
`CalculateCoverageGain`, `IsInterestingInput`); and the Module-4
exploit-pattern generators (`GenerateHeapSprayPattern`,
`GenerateRopChainPattern`, `GeneratePrivilegeEscalationPattern`,
`GenerateCodeInjectionPattern`, `CalculatePatternConfidence`,
`ValidateFaultPattern`). `SimulateRaceCondition` (invoked every iteration
via `SimulateRaceConditions`) is an unimplemented stub. Each of these is
marked `NOT WIRED` / `STUB` in the source at its definition.

In short: the "coverage bitmap fed back into the mutator" feedback loop
described above as the design intent does not exist in the run path
today, and the fault-pattern classifier only ever emits UAF records in
practice. Treat the five-module list as the architecture the code is
organized around, not as a description of what a live campaign produces.

## Architecture

```
+-----------------------------+
|       Python client         |
|   (config / IOCTL driver /  |
|    real-time monitoring)    |
+-------------+---------------+
              | DeviceIoControl
              v
+-----------------------------+
|        Kernel driver        |
|   ThreadInterleavingSim     |
|   SharedResourceMutator     |
|   RaceDetector (lockset)    |
|   FaultPatternGenerator     |
|   CoverageTracker           |
+-----------------------------+
```

## Build

The driver builds with the WDK toolchain on Windows; the `sources`
file under `src/` describes the build for the legacy WDK build
environment. From `src/`:

```cmd
build.bat                    # WDK build (legacy `sources`)
:: ── sign the driver before installing — see SIGNING.md ──
install.bat                  # sc create + sc start (requires admin)
python client.py             # user-space monitor
uninstall.bat                # tear down
```

> **Driver signing is required before `install.bat` will succeed.**
> Windows refuses to load unsigned kernel drivers, so `sc start
> KernelFuzzer` fails with `ERROR_INVALID_IMAGE_HASH` on a clean
> system. Follow [`SIGNING.md`](./SIGNING.md) once per host to:
>
> 1. enable test-signing (`bcdedit /set testsigning on` + reboot);
> 2. create a self-signed code-signing certificate via
>    `New-SelfSignedCertificate` and install it into the local
>    Root + TrustedPublisher stores;
> 3. sign `KernelFuzzer.sys` with `signtool sign /fd SHA256 ...`.
>
> Production deployment is out of scope for KRzr — the driver is a
> research artefact for dedicated kernel-debug VMs.

## Verify

The kernel driver needs a privileged VM to exercise, but the user-mode
orchestrator and the repo structure can be checked on any host with no
WDK and no driver loaded:

```cmd
python -m py_compile src\client.py        :: orchestrator parses
pip install -r tests\requirements.txt
python -m pytest tests\ -v                 :: structure + client contract
```

`tests/` asserts the documented files are present, that `install.bat` /
`uninstall.bat` are CWD-independent, and that `client.py`'s
`FuzzingConfig` defaults and IOCTL codes match the values hard-coded in
`kernel_fuzzer.c`'s `DeviceControl` dispatch (checked by value, not
against `kernel_fuzzer.h` — see the note at the top of that header: its
struct layouts have drifted from the `.c` file's local definitions, so
it is documentation, not the compiled contract). 25 tests pass locally
and in CI (`.github/workflows/ci.yml`, `windows-latest`). Importing
`client.py` is safe — its device I/O is under the
`if __name__ == "__main__"` guard. None of this exercises kernel code;
it cannot catch the kernel-side bugs described in "What actually runs"
above.

## Threat Model and Scope

This is a **detection** tool. It surfaces race-condition candidates
and produces structured *classification* records — the
fault-pattern records describe the bug class observed, not weaponised
payloads. The driver must only be loaded on dedicated research VMs /
lab hosts that the operator owns, with test-signing enabled.

The driver does not:

- modify production kernel data structures,
- replace SSDT entries,
- inject code into non-fuzzed processes,
- exfiltrate any data off the host.

It does:

- create paired kernel system threads racing on synthesised shared
  state,
- record lock-acquire / lock-release events into an in-memory
  lockset,
- emit structured records about candidate races to the user-mode
  client.

## Status

Research / non-production, and pre-alpha in capability: only the thin
slice described in "What actually runs" is wired up; most of the module
surface is defined but not called (see above). The driver is intended
for use on a dedicated kernel-debug VM. Output is meant for analyst
review, not for downstream automation. This has not been built or run
on a kernel VM as part of this revision — see BUILD_AND_VERIFY.md for
what has and has not been verified.

## Limitations

- Only a thin slice of the described module surface is wired into the
  running fuzzing loop; see "What actually runs" above for exactly what
  executes versus what is defined-but-dead.
- Race detection is bounded by the lockset abstraction; pure
  happens-before races without lock pairing may go unflagged. The
  lockset path itself only ever sees fixed synthetic addresses, not
  real kernel state.
- The synthetic shared resources are a small set; coverage of the
  full kernel object zoo is out of scope for the current revision.
- No automated test harness — the driver requires a privileged kernel
  environment to exercise; static testability is limited to the
  Python client and the repo structure (25 pytest cases, zero kernel
  code coverage).
- Reported success probabilities in the fault-pattern records are
  heuristic; treat them as classification confidences, not exploit
  feasibility scores. In practice only the UAF pattern class is ever
  emitted by a running campaign (see "What actually runs").
- `IOCTL_CREATE_THREAD`'s client method (`create_thread`) sends a
  4-byte thread ID but the driver requires a full `THREAD_CONTEXT`
  (`inputBufferLength >= sizeof(THREAD_CONTEXT)`), so it always returns
  `STATUS_INVALID_PARAMETER` — that client method cannot currently
  succeed.
- The device is created with `FILE_ANY_ACCESS` and no SDDL/ACL, so any
  user on the box can issue IOCTLs; this is a known open attack surface
  for a tool that should only run on an isolated, single-operator VM.

## References

- B. Jeong, J. Hong, S. Lee, T. Kim, *Razzer: Finding Kernel Race
  Bugs through Fuzzing*, IEEE S&P 2019.
- J. Xu, D. Mu, X. Xing, P. Liu, P. Chen, B. Mao, *Krace: Data Race
  Fuzzing for Kernel File Systems*, IEEE S&P 2020.
- D. Engler, K. Ashcraft, *RacerX: Effective, Static Detection of
  Race Conditions and Deadlocks*, SOSP 2003.
- Microsoft Driver Development Kit — KMDF reference.

## License

MIT — see `LICENSE`.
