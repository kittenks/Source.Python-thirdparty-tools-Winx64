# Source.Python — Windows x86-64 third-party tools

Reproducible Windows x86-64 builds of the third-party dependencies and the
redistributable Python runtime used by the **Source.Python `spWinx64` port**
(<https://github.com/kittenks/Source.Python>, branch `spWinx64>), initially
validated on a real **Counter-Strike: Source Windows x86-64 dedicated server**.

This repository is a build/verification companion. It is **not** a fork of
Source.Python, and it never pushes to, comments on, or opens anything against
the upstream Source.Python project. Everything here targets the `kittenks`
repositories only.

## What it produces

All binaries are MSVC **x86-64, static CRT (/MT), Release**, matching how
`src/makefiles/win32/win32.base.cmake` links Source.Python on Windows x86-64.

| Tool | Version | Source | Outputs |
|---|---|---|---|
| Boost | 1.87.0 | official Boost source tarball | `libboost_{system,filesystem,python313}-vc143-mt-s-x64-1_87.lib` |
| AsmJit | 1.14.0 | `asmjit/asmjit` git tag `1.14.0` | `AsmJit.lib` |
| dyncall | 1.1 | `dyncall/dyncall` git tag `r1.1` | `libdyncall_s.lib`, `libdyncallback_s.lib`, `libdynload_s.lib` |
| DynamicHooks (+HDE64) | spWinx64 | `kittenks/Source.Python@spWinx64` (carries the Win64 fixes) | `DynamicHooks.lib` |
| Python runtime | 3.13.2 | official CPython **embeddable amd64** zip | `Python3/plat-win/*.dll` + `*.pyd` (28 PE-x86-64 files) |

Exact pins, URLs, defines and expected outputs live in
[`manifests/versions.json`](manifests/versions.json).

### Why these sources

- **The Boost / AsmJit / dyncall compile-time libraries are already vendored**
  in Source.Python's `src/thirdparty`. These jobs rebuild them from pinned
  upstream sources on a clean GitHub runner, so the vendored binaries are
  independently reproducible and verifiable instead of being opaque artifacts
  from a single workstation.
- **DynamicHooks and HDE64 compile from source inside Source.Python's CMake** on
  x86-64. The prebuilt library shipped with upstream DynamicHooks was built for
  the System V ABI and cannot work on Windows; the Windows port fixes the x64
  ABI/LLP64 bridge and compiles the sources directly. The DynamicHooks job here
  rebuilds the standalone static library from the exact `spWinx64` sources as an
  independent build check and archive, pulling them from
  `kittenks/Source.Python@spWinx64` (never from upstream DynamicHooks).
- **The Python runtime is the official CPython embeddable distribution, not a
  custom interpreter build.** Rebuilding CPython itself would only risk ABI
  drift with no benefit; the embeddable zip is the standard x86-64 runtime.
  Source.Python ships its own standard library, so the embeddable
  `python313.zip` stdlib archive and the `python313._pth` path file are
  dropped; only the 28 native runtime DLLs and extension modules are packaged
  into the `Python3/plat-win` layout the port loads. This is the exact set
  verified running on the CS:S x64 server.
- The vendored dyncall libraries were originally produced from a 1.2-dev
  `master` snapshot; the Win64 dyncall/dyncallback/dynload backends are
  unchanged between that snapshot and release 1.1, so the formal tagged **1.1**
  release is pinned for reproducibility.

## Running a build (GitHub Actions)

The workflow is **manual only** (`workflow_dispatch`) and **never creates a
release**. Open the **Actions** tab, choose **Build Windows x86-64 third-party
tools**, click **Run workflow**, and tick the tools you want:

- tick every box = build all tools ("select all");
- tick a single box = build just that tool ("select one").

Each selected tool runs as its own job and uploads an independent artifact
(`boost-win64`, `asmjit-win64`, `dyncall-win64`, `dynamichooks-win64`,
`python-runtime-win64`), each with a `SHA256SUMS.txt` manifest. Artifacts are
retained for 90 days and are downloaded from the workflow run; there are no
release binaries during the testing phase. Per-job build logs are visible and
every produced file is hashed, so a rebuild is fully traceable.

## Build order with Source.Python

1. Build/publish the **python-runtime-win64** artifact here first.
2. The Source.Python Windows x86-64 workflow on branch `spWinx64` builds
   `core.dll` / `source-python.dll` directly from its vendored compile-time
   dependencies. For a runnable game server package it downloads
   **python-runtime-win64** and overlays it onto
   `addons/source-python/Python3/plat-win` before packaging. The DLL-only
   artifact does not need the runtime.

## Repository layout

- `manifests/versions.json` — pinned versions, URLs, defines and expected outputs.
- `scripts/` — build/fetch scripts used by the workflow (also runnable locally).
- `console/` — helper utilities, e.g. `console_input.ps1`, which drives a
  Windows srcds console for automated smoke tests.
- `debug/` — archived, **non-official** diagnostics from the porting effort
  (C++ trace copies, analysis scripts, and Source.Python server diagnostic
  plugins). Kept as a backup for porting/debugging other Source-engine games;
  deliberately **not** part of the Source.Python main repository.

## Local reproduction

Each `scripts/*.ps1` is self-contained and parameterized; run it from an "x64
Native Tools for Visual Studio 2022" prompt (or let the script import the VS
dev environment). The workflow shows the exact invocations.

## Status

Validated against a real Counter-Strike: Source Windows x86-64 dedicated server
during the spWinx64 bring-up. This is a testing-phase tooling repository:
expect workflow iteration, and do not treat artifacts as stable releases.
