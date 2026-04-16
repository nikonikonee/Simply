# Simply

Automated Themida unpacker for Windows x64. Feed it a packed exe, get back a working unpacked one with real imports and clean sections.

## Build

Open `Simply.slnx` in Visual Studio 2022, Release x64, build. Needs vcpkg (pulls in minhook for SimplyBypass).

## Run

```
Simply.exe packed.exe output.exe --verbose
```

`SimplyBypass.dll` has to sit next to `Simply.exe`. The output is a valid PE you can run directly or drop into IDA.

## How it works

Two binaries. `Simply.exe` is the host debugger, it spawns the target as a debuggee. `SimplyBypass.dll` is manual-mapped into the target and silences Themida's anti-debug checks before any protected code runs.

```
            +------------------------+
            |      Simply.exe        |
            |    (host debugger)     |
            +-----------+------------+
                        |
          CreateProcess w/ DEBUG_ONLY_THIS_PROCESS
                        v
            +------------------------+
            |   packed target.exe    |
            |      (suspended)       |
            +-----------+------------+
                        |
               manual map bypass
                        v
            +------------------------+
            |    SimplyBypass.dll    |
            | hooks anti-debug APIs  |
            +-----------+------------+
                        |
           strip PAGE_EXECUTE on target .text
                        v
            +------------------------+
            |  target resumes,       |
            |  themida decrypts,     |
            |  jumps to OEP -> AV    |
            +-----------+------------+
                        |
                        v
            +------------------------+
            |  snapshot image,       |
            |  capture api landings, |
            |  rebuild IAT,          |
            |  drop packer sections, |
            |  write output.exe      |
            +------------------------+
```

### Pipeline stages

1. **pe_inspector.** Parse the input PE. Find `.text`, grab `size_of_image`, fingerprint the Themida version from section names.

2. **debugger.** `CreateProcessW` with `DEBUG_ONLY_THIS_PROCESS` so we don't get dragged into themida's child processes. Event loop dispatches `CREATE_PROCESS`, `LOAD_DLL`, `EXCEPTION`, etc. to callbacks in `main.cpp`.

3. **peb_patcher.** Clear `PEB.BeingDebugged`, strip debugger flags in `NtGlobalFlag`, zero heap flags, remove `SeDebugPrivilege` from the target token. Happens before the first target instruction runs.

4. **injector.** Manual-map `SimplyBypass.dll` into the target. Copy sections, apply relocs, resolve imports, build x64 shellcode that calls `DllMain`, kick it off with `NtCreateThreadEx`. Host watches for the shellcode thread's exit event, then reclaims the remote allocations.

5. **oep_finder (the DEP trap).** Once the bypass is live, strip `PAGE_EXECUTE` from the target's `.text`. When themida finishes unpacking and jumps to the real OEP, the CPU raises an access violation on the first instruction fetch. That AV is our stop condition.

   No software breakpoints inside `.themida`, since themida re-encrypts those pages in the background and would clobber an `int3`. Return breakpoints use `DR0` hardware BP.

6. **themida_capture.** At OEP, freeze every target thread. For each themida API stub, run a tiny remote thread with TF set so we record where the VM dispatch lands (the real API). Produces a `stub -> api` map plus a `slot -> stub` map for poisoned IAT entries. Writable pages get snapshotted first and restored afterward, since TF-stepping `_initterm_e` runs static init and dirties `.data`.

7. **dumper.** Read `size_of_image` bytes from the runtime image base. Fix section headers (raw == virtual, `FileAlignment = SectionAlignment`, set `AddressOfEntryPoint`). Then hand off to the rebuild stages in order.

8. **iat_rebuilder.** Walk the dump for qword pointer runs that resolve to exports in modules currently loaded in the target. Build fresh import descriptors, INT, name tables. Append as a new `.simply` section, rewrite the `IMPORT` data directory.

9. **themida_stubs.** Find every `call`/`jmp rel32` in `.text` that lands in a packer section. Peel the `FF25`/`E9`/`EB` chain statically, or fall back to the runtime `stub -> api` map for VM-Macro stubs. Resolved sites get rewritten to jump through a 6-byte `FF25` trampoline emitted in `.simply` slack.

10. **section_cleaner.** Drop trailing packer sections. Middle ones get stubbed to empty but the section header stays (Windows loader rejects VA gaps). Rename blank sections from content (`.text`, `.rdata`, `.data`, `.pdata`). Repack with smaller `FileAlignment` to shrink the file.

### OEP detection

The fault classifier in `oep_finder.cpp` handles five cases:

| case | condition | action |
|---|---|---|
| `RealOep` | exec fault in `.text`, return addr outside `.themida` | stop, start dump |
| `VmSubcall` | exec fault in `.text`, return addr inside `.themida` | themida VM dispatched into .text and will return. disarm DEP, DR0 on return, re-arm on `ReturnBp` |
| `VirtualizedThunk` | first byte of `.text` is a `JMP rel32` into a runtime VM region (Themida Pro EPV) | strip DEP, set TF, let JMP run. re-arm DEP after the SINGLE_STEP, next .text fetch is the real OEP |
| `ReturnBp` | DR0 hit | disarm BP, re-arm DEP, continue |
| `Unrelated` | anything else | reflect to target SEH |

### Anti-debug bypass

`SimplyBypass` hooks a long list of `Nt*` and user32 calls through MinHook:

| target | purpose |
|---|---|
| `NtQueryInformationProcess` | scrub `ProcessDebugPort` / `Handle` / `Flags` |
| `NtSetInformationThread` | swallow `HideFromDebugger` |
| `NtSetInformationProcess` | fake-success `BreakOnTermination` |
| `NtQuerySystemInformation` | fake `NotPresent` for `KernelDebuggerInfo` |
| `NtQueryObject` | zero `DebugObject` counts |
| `NtGetContextThread` / `NtSetContextThread` / `NtContinue` | scrub DRx on every path |
| `NtYieldExecution` | force `STATUS_NO_YIELD_PERFORMED` so timing channels collapse |
| `NtProtectVirtualMemory` | block EXECUTE on our DEP trap range |
| `FindWindow` / `RegOpenKeyEx` | filter debugger class names and registry keys |
| `GetTickCount` / `NtQuerySystemTime` / `NtQueryPerformanceCounter` | synthetic monotonic clock |
| `NtClose` / `DbgUiRemoteBreakin` / `OutputDebugStringA` / `BlockInput` | misc themida tripwires |

## Layout

```
Simply/
  src/main.cpp              state machine, callback wiring
  src/debugger.cpp          WaitForDebugEvent loop
  src/pe_inspector.cpp      PE parse + themida fingerprint
  src/peb_patcher.cpp       PEB + token sanitizing
  src/injector.cpp          manual map + shellcode loader
  src/oep_finder.cpp        DEP trap, DRx, TF, fault classification
  src/themida_capture.cpp   runtime stub -> api capture at OEP
  src/dumper.cpp            raw snapshot, header fixup, rebuild glue
  src/iat_rebuilder.cpp     IAT scan, import descriptor emit
  src/themida_stubs.cpp     static stub chain walk, trampoline emit
  src/section_cleaner.cpp   packer section drop, rename, repack

SimplyBypass/
  dllmain.cpp               hidden-thread bootstrap
  hooks.cpp                 MinHook anti-debug pack
```
