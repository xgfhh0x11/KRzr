# KRzr — Build & Verification

> *This file answers: "Is this project buildable, runnable, and behaving
> as documented?" The repo ships as a single commit, so there is no
> incremental fix history to point to — this document describes the
> current state only.*

KRzr is a Windows kernel-mode race-condition fuzzer. It consists of a
single-translation-unit WDM driver (`src/kernel_fuzzer.c`,
`src/kernel_fuzzer.h`) that exposes a control device `\\.\KernelFuzzer`,
plus a user-mode Python orchestrator (`src/client.py`) that issues IOCTLs
over `DeviceIoControl`. The build is driven from `src/` by the legacy WDK
build environment (`src/sources` + `src/build.bat`); install/uninstall is
done with the Service Control Manager (`sc.exe`).

---

## 1. Build

### 1.1 Primary build path

The repository ships exactly one supported build flow: the **legacy WDK
build environment** (`build.exe`, driven by a `sources` file). All
commands run from `src/`.

- **Platform**: Windows 10/11 x64 host (build host can be the analyst
  workstation; the *target* must be a dedicated kernel-debug VM — see
  §2.3).
- **Toolchain**:
  - Windows Driver Kit (WDK) — the `sources`-file build environment.
    `src/build.bat` probes the path
    `C:\Program Files (x86)\Windows Kits\10\bin\x64\setenv.cmd` and
    aborts if it is missing.
  - The legacy `build.exe` driven by `setenv.cmd /Release /x64`. This
    is the **WDK 7.1-style** flow; modern WDK 10 ships MSBuild-based
    `.vcxproj` projects instead, so this command line only succeeds on
    a host that still has the legacy `build`/`sources` flow installed.
  - Python 3.x with the standard library (`ctypes`, `struct`,
    `threading`) — no extra `pip` packages required by `client.py`.
- **Command** (from an elevated `cmd.exe` in `src/`):
  ```cmd
  build.bat
  ```
  which internally executes:
  ```cmd
  call "C:\Program Files (x86)\Windows Kits\10\bin\x64\setenv.cmd" /Release /x64
  build -ceZ
  ```
- **Output**:
  - `src\objfre_win7_amd64\amd64\KernelFuzzer.sys` — the signed-or-unsigned driver image (path is hard-coded in `build.bat` and `install.bat`).
  - `*.pdb`, `*.obj`, `*.log`, `*.wrn`, `*.err` in the same `objfre_*` tree (all listed in `.gitignore`).
- **Required**:
  - Administrator command prompt for `install.bat` / `uninstall.bat`
    (they call `net session` to confirm).
  - x64 Windows kernel-debug target VM with **test-signing enabled**
    (`bcdedit /set testsigning on`, reboot) — required because no Microsoft
    Attestation signing is performed.
  - The driver `.sys` must be signed with a self-signed test certificate
    via `signtool sign /fd SHA256 /v /s PrivateCertStore /n <name> /t http://timestamp.digicert.com KernelFuzzer.sys` — the full 5-step recipe (test-signing enable → cert generation → export+trust → sign → install+verify) is documented in `SIGNING.md` at the project root, and the README Build section now references it.
- **Optional**:
  - WinDbg / KD on the host for live kernel debugging of the target VM.
  - DebugView (Sysinternals) on the target to capture `DbgPrint` output emitted by `LogMessage` (see `kernel_fuzzer.h`, §LOG_INFO/LOG_ERROR macros).

### 1.2 Alternative build paths

- **Modern WDK 10 / MSBuild via `.vcxproj`**: not provided. A reviewer
  who only has the modern WDK installed must either (a) install the
  legacy build environment, or (b) hand-author a KMDF `.vcxproj` that
  compiles `kernel_fuzzer.c` with `ntoskrnl.lib` and `hal.lib` (the
  libraries already named in `src/sources`) and produces
  `KernelFuzzer.sys`. The header `kernel_fuzzer.h` includes
  `<ntddk.h>`, `<ntstrsafe.h>`, `<ntifs.h>`, `<windef.h>` — all standard
  WDK headers.
- **Cross-compilation / WSL / clang-cl**: not supported. Windows kernel
  drivers must be built with the MSVC toolchain on Windows.
- **Python client in isolation** (no driver loaded): `python client.py`
  will run up to the `CreateFileW(\\\\.\\KernelFuzzer, …)` call and then
  fail with `Failed to open device: 2` (ERROR_FILE_NOT_FOUND). This is
  the only static testability path available without a kernel target,
  and the README acknowledges it ("static testability is limited to the
  Python client").

### 1.3 Dependencies

| Dependency | Version / source | Used by | Required? |
|---|---|---|---|
| Windows Driver Kit (legacy `sources`/`build.exe`) | WDK 7.1 / EWDK with legacy env | `build.bat` | Yes — hard-coded path in `build.bat` |
| MSVC kernel-mode toolchain (x64) | shipped inside the WDK | `build.exe -ceZ` | Yes |
| `ntoskrnl.lib`, `hal.lib` | WDK lib path | declared in `src/sources` | Yes |
| Windows 10/11 x64 (build host) | any current build | `build.bat`, `setenv.cmd` | Yes |
| Dedicated kernel-debug target VM | Windows 10/11 x64 with test-signing | runtime | Yes — README §"Threat Model and Scope" |
| Python 3.x | any 3.x | `client.py` | Yes — for runtime verification |
| `signtool.exe` + test certificate | WDK / Windows SDK | manual signing step, recipe in `SIGNING.md` | Yes (not automated; documented) |
| `SIGNING.md` (project root) | this repo | step-by-step test-signing recipe consumed during §2.3 step 3 | Yes — required reading before first install |
| `sc.exe` | in-box | `install.bat` / `uninstall.bat` | Yes |
| WinDbg / KD | Windows SDK | debugging | Optional |
| DebugView | Sysinternals | viewing `DbgPrint` output | Optional |

No third-party libraries. No `pip install` step. No package manifest
(`requirements.txt`, `pyproject.toml`) — `client.py` is stdlib-only.

---

## 2. Expected behavior

### 2.1 What this project does

- A WDM driver (`KernelFuzzer.sys`) registers a device object at
  `\Device\KernelFuzzer` with symbolic link `\DosDevices\KernelFuzzer`
  (confirmed in `kernel_fuzzer.c` line 350/354), exposing the control
  surface `\\.\KernelFuzzer` to user mode.
- The source is organized around five module-shaped groups of functions
  (see the README), but **only a thin slice is actually wired into the
  running fuzzing loop** — see README "What actually runs" for the exact
  breakdown. In summary:
  1. **Thread Interleaving Simulator** — wired: `PsCreateSystemThread`,
     CPU affinity / priority, `KeDelayExecutionThread`-based jitter.
  2. **Shared Resource Mutator** — wired: kernel pool, file, registry,
     named pipe, section, mutex, event, semaphore objects (enum
     `RESOURCE_TYPE`).
  3. **Race Detector** — partially wired: the lockset path
     (`RecordMemoryAccess`, `RecordLockAcquisition` → Eraser-style
     state machine) runs on fixed synthetic addresses via
     `SimulateThreadRace`. `AnalyzeLockset` and the shadow-table
     memory-safety detectors (UAF/double-free/etc.) are defined but
     never called.
  4. **Fault Pattern Generator** — partially wired: `SynthesizeFaultPattern`
     runs, but only ever emits `FAULT_PATTERN_USE_AFTER_FREE` records in
     practice (its switch hard-codes that type from the caller, and its
     `default` case also falls back to UAF). The other five
     `FAULT_PATTERN_TYPE` generators (heap-spray, ROP-chain, privilege
     escalation, code injection, double-free) are defined but never
     called from that switch.
  5. **Coverage Tracker** — partially wired: `UpdateCoverage`/
     `HitCoveragePoint` run against a synthetic address, not real
     instrumentation. The Module-5 mutation/feedback engine (`AddInput`,
     `MutateInput`, `CalculateCoverageGain`, …) is defined but never
     called — there is no coverage-guided feedback loop in the run path.
- The user-mode `client.py` opens `\\.\KernelFuzzer`, sends
  `IOCTL_START_FUZZING` with a packed `FUZZING_CONFIG`, then polls
  `IOCTL_GET_STATUS` / `IOCTL_GET_COVERAGE` /
  `IOCTL_GET_FAULT_PATTERNS` on a 1-second loop and surfaces a live
  status line (iterations, races, patterns, coverage %).

### 2.2 Acceptance criteria

The project is "buildable, runnable, behaving as documented" when:

- [ ] `build.bat` exits 0 and writes `src\objfre_win7_amd64\amd64\KernelFuzzer.sys`.
- [ ] `KernelFuzzer.sys` is signed with a trusted test certificate (`signtool verify /pa /v KernelFuzzer.sys` succeeds against a cert in the test-signing trust store).
- [ ] On a target VM with `bcdedit /set testsigning on` set and rebooted, `install.bat` (as admin) creates and starts service `KernelFuzzer` (`sc query KernelFuzzer` reports `STATE: 4 RUNNING`).
- [ ] The symbolic link `\\.\KernelFuzzer` is openable from user mode (`client.py` log line `Connected to kernel driver`).
- [ ] `python client.py` issues `IOCTL_START_FUZZING` and the kernel returns success (log line `Fuzzing started in kernel`).
- [ ] Within the 10-second `main()` window in `client.py`, the status callback prints at least one line with non-zero `Iterations` (proves the kernel `FuzzingLoop` is making progress).
- [ ] `uninstall.bat` stops and deletes the service cleanly (`sc query KernelFuzzer` returns "service does not exist").
- [ ] No host-side Bug Check (BSOD) during the run — kernel race fuzzers can themselves induce crashes; the absence of one with `client.py`'s default 1000-iteration / 30-second-timeout config is the smoke-test pass criterion.

### 2.3 Manual verification

Run on a dedicated kernel-debug VM (snapshot first):

1. **Prepare target VM** (one-time):
   ```cmd
   bcdedit /set testsigning on
   bcdedit /debug on
   bcdedit /dbgsettings serial debugport:1 baudrate:115200
   shutdown /r /t 0
   ```
2. **Build** (host or VM, elevated `cmd.exe` in `src/`):
   ```cmd
   build.bat
   ```
   Verify: `dir objfre_win7_amd64\amd64\KernelFuzzer.sys` returns a non-zero-byte file.
3. **Sign** — full recipe in `SIGNING.md` (project root). Quick form:
   ```powershell
   # Preferred (PowerShell, Win10+):
   $c = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=KRzrTestCert" `
        -CertStoreLocation Cert:\CurrentUser\My -KeyUsage DigitalSignature `
        -KeyExportPolicy Exportable -HashAlgorithm SHA256
   Export-Certificate -Cert $c -FilePath KRzrTestCert.cer
   certutil -addstore Root            KRzrTestCert.cer
   certutil -addstore TrustedPublisher KRzrTestCert.cer
   signtool sign /fd SHA256 /a /s My /n KRzrTestCert `
        /t http://timestamp.digicert.com objfre_win7_amd64\amd64\KernelFuzzer.sys
   ```
   Legacy `makecert` fallback and troubleshooting (incl. `ERROR_INVALID_IMAGE_HASH`
   / `0xC0000428`) are covered in `SIGNING.md`.
4. **Install & start** (elevated `cmd.exe` on the VM, from `src/`):
   ```cmd
   install.bat
   ```
   Verify: `sc query KernelFuzzer` reports `STATE: 4 RUNNING`.
5. **Exercise**:
   ```cmd
   python client.py
   ```
   Expected stdout (paraphrased):
   ```
   Connected to kernel driver
   Kernel fuzzing started
   Status: Iterations=<n>, Races=<m>, Patterns=<p>, Coverage=<c>%
   ... (repeats ~10x at 1 Hz) ...
   Kernel fuzzing stopped
   Final status: FuzzingStatus(is_running=False, iterations_completed=<n>, ...)
   ```
6. **Tear down**:
   ```cmd
   uninstall.bat
   ```
   Verify: `sc query KernelFuzzer` returns service-not-found.
7. **Snapshot revert** (recommended) — the driver allocates kernel pool
   with tag `'FZAR'` (`RACE_FUZZER_TAG`) and creates kernel system
   threads; while `DriverUnload` should clean up, a fresh VM state per
   campaign is safer.

### 2.4 Automated verification

**There is no automated test harness in the repository.** The README
explicitly acknowledges this (§Limitations: *"No automated test harness
— the driver requires a privileged kernel environment to exercise;
static testability is limited to the Python client."*).

Static checks that *could* be run today without a target VM:

- **Python syntax / import check** (host):
  ```cmd
  python -m py_compile src\client.py
  ```
  Expected: exit code 0, no output. (This validates the orchestrator
  parses, but does not exercise any IOCTL path.)
- **Driver headers present**: `dir src\kernel_fuzzer.c src\kernel_fuzzer.h src\sources src\build.bat`. All four must exist.
- **IOCTL-code parity** between `client.py` and `kernel_fuzzer.h`:
  Both define `KERNEL_FUZZER_DEVICE_TYPE = 0x8000`. The Python side
  hard-codes `IOCTL_START_FUZZING = 0x80002000` etc.; the kernel side
  builds them via `CTL_CODE(0x8000, 0x800, METHOD_BUFFERED,
  FILE_ANY_ACCESS) = 0x80002000`. These match — confirmed by manual
  expansion of the `CTL_CODE` macro.

See §3.3 for the proposed automated harness.

---

## 3. Alternatives & improvements

### 3.1 Known fragilities

- **Test-signing is documented.** `SIGNING.md` ships at the project root
  with a 5-step test-signing recipe (`bcdedit /set testsigning on` →
  `New-SelfSignedCertificate` with `makecert` fallback →
  `Export-Certificate` + `certutil -addstore Root/TrustedPublisher` →
  `signtool sign /fd SHA256` → install + verify), a troubleshooting
  table, and a tear-down section. The README Build section references
  `SIGNING.md` and warns about `ERROR_INVALID_IMAGE_HASH` (`0xC0000428`).
- **Legacy `sources`/`build.exe` toolchain is deprecated.** Modern WDK
  10 installs default to MSBuild + `.vcxproj`. `build.bat` probes
  `setenv.cmd` under the **WDK 10** path (`Windows Kits\10\bin\x64`)
  but invokes the **WDK 7.1-era** `build -ceZ` command — these are
  inconsistent on most modern installs. ⚠️
- **Driver type is WDM, not KMDF.** Implementation grep confirms
  `DriverEntry` + `IRP_MJ_*` dispatch with no `WdfDriverCreate`; the
  README and `sources` (`DRIVERTYPE=WDM`) agree on "WDM", matching the
  C source's raw WDM primitives (`IoCreateDevice`,
  `PsCreateSystemThread`, `KSPIN_LOCK`, `KeDelayExecutionThread`).
- **Output path is hard-coded** (`objfre_win7_amd64\amd64\KernelFuzzer.sys`)
  in both `build.bat` (echo only) and `install.bat` (actual
  `sc create binPath=…`). If the WDK build environment selects a
  different output folder (e.g. `objchk_win10_amd64`), `install.bat`
  will silently fail to find the artifact. ⚠️
- **`install.bat` uses `%CD%` for `binPath=`.** Running `install.bat`
  from a directory other than `src/` will register a service pointing
  at a non-existent path. The README's snippet implies `cd src` first
  but does not state it explicitly.
- **No `.inf` file.** Although `sc create type= kernel` is sufficient
  for legacy driver loading, distribution via WHQL / driver-store
  install (`pnputil`, `INF`) is not possible without one. This limits
  the install flow to the legacy SCM path.
- **`DriverUnload`/`CleanupResources` do not fully tear down.**
  `CleanupResources()` frees the coverage-point and fault-pattern
  lists but never frees `g_ThreadList` or `g_ResourceList` (their
  `DestroyFuzzingThread`/`DestroyResource` counterparts are declared in
  `kernel_fuzzer.c` but never implemented or called), and
  `DriverUnload()` does not wait for `FuzzingLoop` or any
  `ThreadWorker` thread to exit before deleting the device — threads
  still running after unload touch freed globals / unloaded code. This
  is a known correctness gap, not verified-safe teardown; confirm with
  WinDbg (`!poolused 4 FZAR`) before trusting `sc stop KernelFuzzer` /
  unload on a live VM. ⚠️
- **Driver has no kernel-side bound checks on user buffer sizes** for
  some IOCTLs (e.g. `IOCTL_SIMULATE_RACE` receives a variable-length
  `thread_ids` array). This is a kernel-attack-surface concern even on
  a research VM; the device is created with `FILE_ANY_ACCESS`, so any
  user on the box can issue IOCTLs.

### 3.2 Fallbacks

- **No legacy WDK available**: hand-author a modern KMDF `.vcxproj`
  that adds `kernel_fuzzer.c` as the only `.c` source, links
  `ntoskrnl.lib`+`hal.lib`, sets `Target OS Version = Windows 10`,
  `Driver Type = WDM`, signs with a test certificate, and emits
  `KernelFuzzer.sys`. Most of the work is the project XML; the source
  itself is build-system-agnostic.
- **No kernel-debug VM**: limit verification to §2.4 static checks plus
  `python -c "import src.client; print('import ok')"` — this verifies
  the orchestrator parses but cannot exercise any kernel path. State
  this limitation plainly wherever this project's status is reported.
- **Cannot test-sign**: an alternative on Windows 10/11 dev hosts is
  `bcdedit /set nointegritychecks on` (deprecated, may not work on
  modern builds with Secure Boot) — last resort; prefer the
  test-signing + self-signed cert flow.
- **Driver causes BSOD**: revert VM snapshot. Re-run with
  `client.FuzzingConfig(max_iterations=100, max_threads=2)` to reduce
  load and bisect.

### 3.3 Roadmap

- **Already in the repo**:
  - `SIGNING.md` ships at project root with the 5-step test-signing
    recipe; README Build section references it and warns about
    `ERROR_INVALID_IMAGE_HASH` (`0xC0000428`).
  - README and `sources` agree the driver is WDM (not KMDF).
  - README has a "Verify" section; `py_compile` runs in CI and a
    `tests/` pytest suite (25 cases) checks structure and the
    `client.py` IOCTL/config contract, including mocking
    `kernel32.DeviceIoControl` to exercise the packed-struct round-trips
    (`tests/test_client_ioctl.py`): the 8-ULONG config sent on
    `IOCTL_START_FUZZING` and the 9-ULONG status parsed from
    `IOCTL_GET_STATUS`.
  - `install.bat` / `uninstall.bat` `cd /d "%~dp0"` first, so they work
    regardless of the caller's CWD (also fixes the `%CD%`-based
    `binPath` in `install.bat`); locked in by `tests/test_structure.py`.
  - `IOCTL_ALLOCATE_MEMORY`, `IOCTL_FREE_MEMORY`, `IOCTL_GET_COVERAGE`,
    and `IOCTL_GET_FAULT_PATTERNS` now have real implementations behind
    them (previously `status = STATUS_SUCCESS` no-ops that left the
    client's output buffers zeroed); `IOCTL_CREATE_MUTEX` and
    `IOCTL_SIMULATE_RACE` remain intentional no-ops (no client-side
    caller/output contract exists to implement against — see comments
    at their `DeviceControl` case).
  - The three use-after-return bugs in `CreateFuzzingThreads`,
    `CreateFuzzingResources`, and `SynthesizeFaultPatterns` (stack
    locals handed to global lists / live threads) are fixed by
    heap-allocating the contexts instead.
- **Not yet done**:
  - Ship a modern WDK 10 MSBuild `KernelFuzzer.vcxproj` alongside the
    legacy `sources` file so reviewers with a stock WDK install can
    build without installing the legacy environment.
  - Pin IOCTL codes in `client.py` against the `CTL_CODE` expansion of
    `kernel_fuzzer.h` in a generated header (`ioctls.py`) to prevent
    drift — moot until `kernel_fuzzer.h`'s struct layouts are reconciled
    with the `.c` file's local definitions (see the note at the top of
    `kernel_fuzzer.h`).
  - Real thread teardown: reference and wait on every `ThreadWorker` /
    `FuzzingLoop` thread before `DriverUnload` frees anything (see §3.1).
  - Wire the shadow-table memory-safety detectors, `AnalyzeLockset`, the
    Module-5 mutation/feedback engine, and the Module-4 exploit-pattern
    generators into a live path, or remove them if they are not going to
    be — see README "What actually runs" for the current list of
    defined-but-dead code.
  - Provide a Vagrant / Hyper-V automation script that builds a
    test-signing-enabled Windows VM, deploys `KernelFuzzer.sys`, runs
    `client.py` for a fixed campaign, harvests fault-pattern records,
    and reverts the snapshot — a real CI lane for a kernel research
    artefact.
  - Replace the lockset abstraction with a happens-before /
    vector-clock detector as called out in README §Limitations.
  - Tighten the device-creation ACL (currently `FILE_ANY_ACCESS`) so
    only `SeDebugPrivilege` holders can issue IOCTLs.

---

## 4. Sanity check

| Check | Status | Notes |
|-------|--------|-------|
| README documents build | ✅ | README §Build lists `build.bat` / `install.bat` / `client.py` / `uninstall.bat`, references the `sources` file, references `SIGNING.md` for the test-signing recipe, and warns about `ERROR_INVALID_IMAGE_HASH` (`0xC0000428`). |
| Build files present | ✅ | `src/build.bat`, `src/install.bat`, `src/uninstall.bat`, `src/sources` all exist. |
| Build files internally consistent | ⚠️ | `build.bat` probes the WDK 10 `setenv.cmd` path but invokes the WDK 7.1 `build -ceZ` legacy flow. Output path `objfre_win7_amd64\amd64` is hard-coded in both `build.bat` and `install.bat` — consistent with each other but brittle vs. modern WDK build-tree layouts. (README and `sources` agree on `DRIVERTYPE=WDM` — no KMDF/WDM mismatch.) |
| Source structure matches README | ✅ | README (now correctly) describes a single-file WDM driver + Python client; repo has `kernel_fuzzer.c` (37 KB) + `kernel_fuzzer.h` + `client.py`. README's five-module breakdown maps cleanly to enums/prototypes in `kernel_fuzzer.h`. |
| Tests exist | ✅ | `tests/` (pytest): `test_structure.py` (documented files + CWD-independence of the service scripts), `test_client.py` (imports `client.py`, asserts `FuzzingConfig` defaults + IOCTL codes vs the values hard-coded in `kernel_fuzzer.c`), and `test_client_ioctl.py` (mocked `DeviceIoControl` packed-struct round-trips). 25 passed locally. Driver self-test IOCTL still absent (needs a kernel VM); zero kernel code is exercised by this suite. |
| Test invocation documented | ✅ | README has a "Verify" section (`py_compile` + `pytest`); CI (`.github/workflows/ci.yml`, `windows-latest`) runs both. The manual driver flow (`build.bat` → `SIGNING.md` → `install.bat` → `client.py` → `uninstall.bat`) remains documented for the privileged path. |
| Output artifacts named in build files | ✅ | `src/sources` declares `TARGETNAME=KernelFuzzer` and `TARGETTYPE=DRIVER`; `build.bat` echoes and `install.bat` consumes the path `objfre_win7_amd64\amd64\KernelFuzzer.sys`. |
