# Source.Python Windows x86-64 port — diagnostic archive

This `debug/` directory is an **archive of the non-upstream diagnostic tools**
that were used while porting Source.Python to 64-bit Windows and stabilizing it
on a real **Counter-Strike: Source `srcds_win64`** dedicated server.

Nothing in here is part of Source.Python. None of it is loaded by default, none
of it is shipped in the main `Source.Python` repository, and none of it was ever
sent upstream. It is kept because the same class of problems (wrong-ABI hook
bridges, short-function detours, architecture-specific gamedata) shows up again
when porting to any other 64-bit Source game, and these tools answer those
questions quickly.

## Layout

```
debug/
  cpp-trace/         Instrumented copies of SP/DynamicHooks sources (heavy tracing)
  server-plugins/    One-off Source.Python Python plugins, dropped into the server's plugins/ dir
  analysis-scripts/  Standalone Python/PowerShell/C++ helpers and captured logs
```

Paths under `cpp-trace/` mirror the Source.Python repository layout so a file can
be diffed directly against the clean `spWinx64` tree.

## cpp-trace/ — instrumented source snapshots

These are the *diagnostic* versions of files that ship clean in `spWinx64`. They
contain a vectored-exception-handler watchpoint, a sampling thread, per-hook
register/stack snapshots (`SNAP`), hard-coded `fopen` trace logs, and the
hibernation vtable/byte dumper. They were used to localize the crashes and are
retained for reference only — do **not** copy them over the shipping sources.

| File | What the instrumentation revealed |
| --- | --- |
| `src/thirdparty/DynamicHooks/src/hook_x64.cpp` | The Win64 JIT hook bridge. Showed handler arguments arriving in the System V registers (rdi/rsi/rdx) instead of the MS x64 registers (rcx/rdx/r8/r9), and the missing 32-byte shadow space that flipped RSP alignment and crashed inside `movaps`. |
| `src/core/modules/memory/memory_hooks.cpp` / `.h` | VEH + write-protect watchpoint + sampling thread proving the hooked convention was never freed and still held a valid `x64MsWin64` vtable right up to the fault (exonerating the ownership path). |
| `src/core/modules/memory/memory_function.cpp` | Convention lifetime/ownership trace around hook hand-off and `~CFunction`. |
| `src/core/sp_main.cpp`, `src/core/sp_hooks.cpp` | Bisection harness that isolated `CBasePlayer::PlayerRunCommand` (gamedata key `run_command`, server.dll RVA `0x3107A0`) as the hook that crashed when a second bot dispatched. |
| `src/core/modules/entities/entities_transmit.cpp` | High-frequency `CheckTransmit` tick used as a liveness sample just before the crash. |
| `addons/source-python/packages/source-python/listeners/__init__.py` | The hibernation-hook bring-up: vtable/object/function dumps and raw prologue bytes for `IServerGameDLL::SetServerHibernation`. |

### The one diagnostic that is kept in the shipping code

The DynamicHooks x64 "report the function address and the first bytes when a
terminal instruction is found before the detour boundary" diagnostic is kept in
`hook_x64.cpp`, but behind a **compile-time** switch, off by default:

- CMake option `SP_HOOK_DIAG` (default `OFF`).
- Configure with `-DSP_HOOK_DIAG=ON`; this defines `DYNAMICHOOKS_DIAG=1` for the
  `core` target and restores the verbose address/byte exception message.

It is deliberately **not** a runtime ConVar: this code runs while hooks are
being installed at startup, inside the third-party DynamicHooks translation
unit, before Source.Python registers any ConVar, and core has no C++ global
ConVar registration pattern. A build-time switch is the earliest, simplest
point that can reach it.

## server-plugins/ — one-off in-server plugins

Copy a plugin folder into
`cstrike/addons/source-python/plugins/` and load it with `sp plugin load <name>`;
unload/remove it when finished. They write their output under
`cstrike/logs/source-python/`.

| Plugin | Purpose |
| --- | --- |
| `sp_console` | Captures what Source.Python is doing in real time and attributes every faulting address to a module + RVA. Built to turn hundreds of bare `Access violation while executing address '...'` lines into something actionable. |
| `sp_addrguard` | Proves on the live server whether a function pointer survives intact from the vtable into the call (the faulting address was the low 32 bits of the real address). |
| `sp_vtable` | Records which Python code reads a virtual-function property and which vtable index/offset it asked for (used to identify vtable slot 171 / byte offset 1368). |
| `sp_vtable_probe` | Asks RTTI what the vtable indices really are and compares them against the data-file declarations. |
| `sp_stride` | Decides whether a virtual call lands on the wrong function and why (cross-checks e.g. `PhysicsSolidMaskForEntity`, slot 171, against the SDK headers). |
| `sp_hibprobe` | One-shot, read-only: resolves `CServerGameDLL::SetServerHibernation` exactly as `listeners.__init__` does and dumps the real target, module + RVA, and the first prologue bytes to explain the `Terminating control flow appears before the detour boundary` warning. |
| `sp_compat` | Generates a per-game compatibility report by scanning `data/source-python/**/*.ini` and resolving each architecture-specific signature/name through the three-level `<key>_<platform>_<arch>` → `<key>_<platform>` → `<key>` fallback in `memory/helpers.py`. |

## analysis-scripts/ — offline helpers and captured logs

- `find_hib.py`, `find_hib2.py`, `find_hib3.py`, `find_hib4.py` (+ `*_out.txt`),
  `find_hib_cvar.py`, `find_cvars.py` — PE/capstone scans of `server.dll` to
  locate the hibernation setter and to enumerate ConVars (used to prove
  `sv_hibernate_when_empty` does **not** exist in CS:S; it is a CS:GO ConVar).
- `disasm_bridge.py`, `disasm_core.py` — capstone/Ghidra disassembly bridges.
- `cdb_script.txt`, `cdb_out.txt`, `cdb_boot.txt` — WinDbg/cdb debugger sessions
  and transcripts.
- `rcon.py` — minimal RCON client used to drive hibernation/bot joins remotely.
- `boot.txt`, `booterr.txt`, `trace.txt` — captured boot and trace output.
- `compare-exports.ps1`, `compare-symbols.ps1` — compare DLL exports/symbols to
  detect ABI mismatches (this is how the System V vs MS x64 DynamicHooks library
  was spotted).
- `verify_boost_x64.cpp`, `verify_boost_python_x64.cpp`, `probe_boost_range.cpp`
  — tiny C++ programs that verify the self-built x64 Boost libraries link,
  export the right symbols, and meet `BOOST_PYTHON_MAX_ARITY`.

## Root causes recorded by these tools

1. **Bot-join crash (DynamicHooks Win64 bridge, ABI).** The prebuilt
   `win64/DynamicHooks.lib` had been built with the System V x64 convention: its
   bridge passed handler arguments in rdi/rsi/rdx and reserved no shadow space.
   On Windows x64 the first arguments are in rcx/rdx/r8/r9 with a mandatory
   32-byte shadow space. Every detour therefore called the MSVC C++ handler with
   the wrong registers and a misaligned RSP, crashing in `movaps` as soon as a
   second bot dispatched `PlayerRunCommand`. The fix builds DynamicHooks
   (`hook_x64.cpp`, `manager.cpp`, `registers.cpp`, `x64MsWin64.cpp`) and the
   HDE64 disassembler (`hde64.c`, compiled as C) directly into `core` on x86-64
   via CMake, instead of linking the prebuilt library.
2. **Hibernation-hook warning (short function).**
   `CServerGameDLL::SetServerHibernation(bool)` is a 4-byte setter
   (`88 51 10 C3` followed by padding) in the 64-bit `server.dll` — shorter than
   the 14-byte absolute detour. The old 5-byte near relay could not be allocated
   within range of the high-based `server.dll` and raised a `RuntimeError` that
   the Python `except (OSError, ValueError)` did not catch. The fix uses a
   14-byte `FF 25` + absolute-64 jump when the function is long enough and
   widens the exception handling.

## Notes on hibernation behavior

Source.Python does not poll for hibernation. It detours the engine callback
`IServerGameDLL::SetServerHibernation(bool)` (`true` = going to sleep,
`false` = waking). CS:S has no `sv_hibernate_when_empty`; for an unattended
server that should keep bots joined without a human present, use the bot
ConVars instead, notably `bot_join_after_player 0` together with
`bot_quota_mode fill` and a `bot_quota` value.
