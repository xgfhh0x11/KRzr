# KRzr kernel-test  -  dynamic test infrastructure

Scripts + runbook for exercising the KRzr driver dynamically on a
**disposable** Hyper-V kdnet guest ("WinKDbg"), from a host that has
`kd.exe`/`kdnet.exe`, the WDK, and MSBuild.

**Nothing in this directory connects to a VM, loads a driver, or runs
anything by itself.** Every script here is a local tool the operator runs
by hand, at the point in the runbook below where it belongs. `build.ps1`
runs on the host. `load.ps1`, `unload.ps1`, and `smoke-test.ps1` are meant
to run **inside** the guest, and default to a dry run  -  they require an
explicit `-Arm` flag to actually touch the driver.

See also: `../README.md` (what the driver claims to do and what's
actually wired), `../BUILD_AND_VERIFY.md` (build/toolchain detail),
`../SIGNING.md` (test-signing + driver-signing recipe).

---

## Why this needs a disposable guest

KRzr is a **race-condition fuzzer**. By its nature it is more likely than
most drivers to bugcheck the machine it runs on  -  and the current code
has documented ways to do exactly that even outside of intentional
fuzzing:

- `DriverUnload`/`CleanupResources` do not wait for the `FuzzingLoop` or
  `ThreadWorker` system threads to exit before the device object and
  driver image are torn down. A thread still running past unload touches
  freed globals / unloaded code.
- `g_ThreadList` and `g_ResourceList` are never freed on unload (their
  `DestroyFuzzingThread()`/`DestroyResource()` counterparts are declared
  but never called)  -  every load leaks kernel pool and thread objects
  that never get reclaimed by unloading.
- The three original use-after-return sites (stack-local contexts handed
  to live threads / inserted into global lists) have been fixed by
  heap-allocating those contexts, but the unload-race and the list leak
  above are still open. See `../README.md` and `../BUILD_AND_VERIFY.md`
  Section 3.1 for the full, current list of known gaps.

None of this is exploit development  -  it's exactly the kind of behavior a
defensive dynamic test pass is meant to surface. Treat every run as
capable of bugchecking the guest, and never run it anywhere you can't
afford to lose.

---

## SAFETY (read this before doing anything else)

1. **Checkpoint the guest FIRST, before enabling test-signing, before any
   build/copy, before the first load.** From the Hyper-V host:
   ```powershell
   Checkpoint-VM -Name WinKDbg -SnapshotName "pre-testsigning-clean"
   ```
   Take a **new** checkpoint again right after the guest is prepared
   (test-signing on, kdnet configured, rebooted, verified stable) so you
   always have a fast, known-good revert point that doesn't require
   redoing setup:
   ```powershell
   Checkpoint-VM -Name WinKDbg -SnapshotName "kdnet-ready-pre-load"
   ```
2. **Prefer revert-to-checkpoint over repeated load/unload cycles in the
   same guest session.** Because of the documented `g_ThreadList` /
   `g_ResourceList` leak and the missing unload-time thread wait (above),
   each unload leaves the guest a little dirtier than it was, and an
   unload racing a live worker thread can itself bugcheck the box. One
   load -> one test pass -> revert to `kdnet-ready-pre-load` is the safe
   pattern. Don't chain `load.ps1` -> `unload.ps1` -> `load.ps1` -> ... in
   one guest boot and trust the state in between.
3. **If the guest bugchecks or hangs at any point**: don't reboot and
   continue. Revert the checkpoint:
   ```powershell
   Restore-VMCheckpoint -VMName WinKDbg -Name "kdnet-ready-pre-load" -Confirm:$false
   ```
4. **Never run anything in this directory against a machine that isn't
   the disposable guest.** `load.ps1` and `smoke-test.ps1` both require
   `-Arm` for exactly this reason  -  the default is always a dry run that
   only prints what it would do.
5. Keep the device's attack surface in mind even inside the guest: KRzr
   creates `\\.\KernelFuzzer` with `FILE_ANY_ACCESS` and no ACL  -  any
   local user/process on the guest can drive it. That's fine for a
   disposable guest with nothing sensitive on it; don't reuse this guest
   for anything else afterward.

---

## Runbook

### 0. One-time guest prep

Inside the guest (WinKDbg), elevated:

```cmd
bcdedit /set testsigning on
bcdedit /debug on
bcdedit /dbgsettings net hostip:<HOST_IP> port:50000 key:<GENERATE_OR_PICK_A_KEY>
```

(or let `kdnet.exe` from the WDK generate the port/key for you  -  run
`kdnet.exe <HOST_IP> 50000` from the guest, which prints the exact
`bcdedit /dbgsettings` command and the resulting key.)

```cmd
shutdown /r /t 0
```

After reboot, confirm the settings that matter for the rest of this
runbook:

```cmd
bcdedit /dbgsettings
```

Read off `port` and `key` from that output  -  you'll need both for step 3.
Confirm test-signing took (a "Test Mode" watermark appears on the
desktop, or `bcdedit /enum {current} | findstr testsigning` reports
`Yes`).

**Now checkpoint** (see SAFETY Section 1, `kdnet-ready-pre-load`).

### 1. Build (host)

From the host, with WDK + MSBuild installed:

```powershell
cd kernel-test
.\build.ps1
```

This builds `kernel-test/msbuild/KernelFuzzer.vcxproj` (a modern WDK 10
MSBuild driver project that compiles the same `../src/kernel_fuzzer.c`
the repo's legacy `src/build.bat` path compiles) as Release|x64. On
success it prints the full path to the produced `KernelFuzzer.sys`. On
any failure it prints MSBuild's actual errors and exits non-zero  -  it
never prints a success message unless the `.sys` file was actually
produced and found on disk.

Then sign it (see `../SIGNING.md`)  -  `build.ps1` prints the `signtool`
command to use.

### 2. Copy the signed `.sys` into the guest

However you move files to WinKDbg (shared folder, `Copy-VMFile`, etc.)  - 
this is the operator's step, deliberately not scripted here since it
depends on your Hyper-V configuration.

### 3. Attach the kernel debugger (host)

Using the `port`/`key` you read off `bcdedit /dbgsettings` in step 0:

```cmd
kd -k net:port=<PORT>,key=<KEY>
```

Once it breaks in, see `kd-triage.txt` for `.reload`, `!analyze -v`,
`!locks`/`!qlocks`, Driver Verifier setup, and race/deadlock/UAF triage
templates.

### 4. Load the driver (inside the guest)

Dry run first (always the default  -  prints the plan, does nothing):

```powershell
.\load.ps1 -SysPath C:\KRzr\KernelFuzzer.sys
```

Then, only after re-confirming you're on the checkpointed disposable
guest and test-signing is on:

```powershell
.\load.ps1 -SysPath C:\KRzr\KernelFuzzer.sys -Arm
```

This checks `testsigning` is enabled, then `sc create` + `sc start`s the
`KernelFuzzer` service and reports `sc query` output. If `sc start`
doesn't report `RUNNING`, check kd for a bugcheck before retrying  - 
prefer reverting the checkpoint.

### 5. Smoke test (inside the guest, separate window)

Dry run:

```powershell
.\smoke-test.ps1
```

Armed:

```powershell
.\smoke-test.ps1 -Arm
```

Drives `IOCTL_ALLOCATE_MEMORY` / `IOCTL_FREE_MEMORY` /
`IOCTL_GET_COVERAGE` / `IOCTL_GET_FAULT_PATTERNS` through
`../src/client.py`'s own `KernelFuzzerClient` (via `smoke_test.py`, which
imports `client.py` directly rather than reimplementing the IOCTL
contract) and checks the responses are well-formed. See
`smoke_test.py`'s module docstring for exactly what it does and does not
exercise (it does not start the fuzzing loop or create kernel threads).

You can also drive the full documented flow with `python
..\src\client.py` directly (see `../BUILD_AND_VERIFY.md` Section 2.3 step 5)  - 
`smoke-test.ps1` is a narrower, lower-risk sanity check of the four IOCTLs
that have real implementations, not a replacement for that.

### 6. Unload / tear down (inside the guest)

```powershell
.\unload.ps1
```

Stops and deletes the `KernelFuzzer` service. Prints the known-leak
warning every time  -  see "Why this needs a disposable guest" above.
**After one test pass, prefer reverting to the `kdnet-ready-pre-load`
checkpoint over trusting the post-unload state for another run.**

### 7. Revert (host)

```powershell
Restore-VMCheckpoint -VMName WinKDbg -Name "kdnet-ready-pre-load" -Confirm:$false
```

Do this between test passes, and always if step 4/5/6 showed anything
unexpected (bugcheck, hang, service stuck).

---

## Files in this directory

| File | Runs on | Purpose |
|---|---|---|
| `README.md` |  -  | This runbook. |
| `build.ps1` | host | MSBuild Release\|x64 build of `KernelFuzzer.sys`; real errors, no fake success. |
| `msbuild/KernelFuzzer.vcxproj` | host | Modern WDK 10 MSBuild project compiling `../src/kernel_fuzzer.c` (fills a gap noted in `../BUILD_AND_VERIFY.md` Section 3.3). |
| `load.ps1` | guest | `sc create`/`sc start` the `KernelFuzzer` service. `-Arm`-gated, dry-run by default. |
| `unload.ps1` | guest | `sc stop`/`sc delete` the `KernelFuzzer` service, with the known-leak warning. |
| `kd-triage.txt` | host (kd session) | Copy/paste `kd.exe` templates: attach, `!analyze -v`, `!locks`/`!qlocks`, Driver Verifier, breakpoints on the documented bug sites. |
| `smoke-test.ps1` | guest | `-Arm`-gated wrapper that runs `smoke_test.py`. |
| `smoke_test.py` | guest | Drives allocate/free/coverage/fault-pattern IOCTLs via `../src/client.py`'s `KernelFuzzerClient`; checks sane responses. |

---

## Service / driver identifiers (from the current source)

- Service / device name: `KernelFuzzer` (`\\.\KernelFuzzer`,
  `\Device\KernelFuzzer`, `\DosDevices\KernelFuzzer`).
- Driver image: `KernelFuzzer.sys`.
- Pool tag: `'FZAR'` (`RACE_FUZZER_TAG`)  -  useful for `!poolused 4 FZAR`.
- IOCTLs with real kernel logic behind them today: `IOCTL_START_FUZZING`,
  `IOCTL_STOP_FUZZING`, `IOCTL_GET_STATUS`, `IOCTL_CREATE_THREAD`,
  `IOCTL_ALLOCATE_MEMORY`, `IOCTL_FREE_MEMORY`, `IOCTL_GET_COVERAGE`,
  `IOCTL_GET_FAULT_PATTERNS`. `IOCTL_CREATE_MUTEX` and
  `IOCTL_SIMULATE_RACE` are intentional status-only no-ops (no
  client-side output contract exists for them yet  -  see the comments at
  their `DeviceControl` case in `../src/kernel_fuzzer.c`).
- Only a thin slice of the driver runs on the live path: `FuzzingIteration`
  -> `GenerateInput`, `CreateFuzzingResources`, `CreateFuzzingThreads`,
  `SimulateRaceConditions` (a stub), `UpdateCoverage`,
  `DetectRaceConditions`, `SynthesizeFaultPatterns`, `UpdateStatistics`.
  The only live *detection* is the lockset path
  (`ThreadWorker`->`SimulateThreadRace`) on fixed synthetic addresses; the
  shadow-table UAF/double-free detectors, `AnalyzeLockset`, and the
  Module-4/5 mutation and exploit-pattern generators are defined but
  never called. See `../README.md` "What actually runs" for the full
  breakdown  -  worth keeping in mind when interpreting what a dynamic run
  did or didn't exercise.
