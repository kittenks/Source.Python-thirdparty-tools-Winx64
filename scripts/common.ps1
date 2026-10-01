# Common helpers for the Windows x86-64 third-party builds.
# Dot-source from another script with:   . (Join-Path $PSScriptRoot 'common.ps1')
$ErrorActionPreference = 'Stop'

# vctip.exe is the MSVC build-telemetry probe that cl.exe spawns. On the
# headless GitHub Actions Windows runners it occasionally inherits the build
# output pipe and never exits, so the MSBuild/cl build hangs until the job
# timeout (the runner then kills an orphan "vctip" process - observed on the
# asmjit job). It is pure usage telemetry and has no effect on code generation,
# so disable it process-wide; CMake-spawned MSBuild/cl children inherit this.
$env:VCTIPDISABLE = '1'

function Get-ToolsRoot {
    # scripts/ -> repository root
    [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
}

function Get-Versions {
    param([string]$Root = (Get-ToolsRoot))
    Get-Content -LiteralPath (Join-Path $Root 'manifests\versions.json') -Raw | ConvertFrom-Json
}

function New-CleanDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    return [IO.Path]::GetFullPath($Path)
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string]$Path)
    $b = [IO.File]::ReadAllBytes($Path)
    if ($b.Length -lt 64 -or $b[0] -ne 0x4D -or $b[1] -ne 0x5A) {
        throw "Not an MZ/PE image: $Path"
    }
    $peOffset = [BitConverter]::ToInt32($b, 0x3C)
    return [BitConverter]::ToUInt16($b, $peOffset + 4)
}

function Assert-PeX64 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $machine = Get-PeMachine -Path $Path
    if ($machine -ne 0x8664) {
        throw "Expected an x86-64 PE image (0x8664) but got 0x$($machine.ToString('X4')) for $Path"
    }
}

function Download-CheckedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [string]$ExpectedSha256 = ''
    )
    $dir = Split-Path -Parent $OutFile
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    Write-Host "Downloading $Url"
    # curl.exe handles large archives and proxies more predictably here than
    # Invoke-WebRequest; -f makes HTTP errors fail, -L follows redirects.
    & curl.exe -fSL --retry 3 --connect-timeout 30 -o "$OutFile" "$Url"
    if ($LASTEXITCODE -ne 0) { throw "Download failed (curl exit $LASTEXITCODE): $Url" }
    $actual = (Get-FileHash -LiteralPath $OutFile -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
        if ($actual -ne $ExpectedSha256.Trim().ToLowerInvariant()) {
            throw "SHA256 mismatch for $Url`n  expected $($ExpectedSha256.Trim().ToLowerInvariant())`n  actual   $actual"
        }
        Write-Host "SHA256 OK (pinned): $actual"
    }
    else {
        Write-Host "SHA256 (recorded, not yet pinned): $actual"
    }
    return $actual
}

function New-Sha256Manifest {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$ManifestPath
    )
    $root = [IO.Path]::GetFullPath($Directory)
    $lines = Get-ChildItem -LiteralPath $root -Recurse -File |
        Where-Object { $_.FullName -ne $ManifestPath } |
        Sort-Object FullName | ForEach-Object {
            $rel = $_.FullName.Substring($root.Length + 1).Replace('\', '/')
            "$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $rel"
        }
    $lines | Set-Content -LiteralPath $ManifestPath -Encoding ASCII
    Write-Host "Wrote $ManifestPath ($($lines.Count) files)"
}

function Import-VcToolsX64 {
    # Locate vcvars64.bat through vswhere and import its environment into this
    # PowerShell process (a child .bat cannot export env back on its own).
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { throw "vswhere.exe not found at $vswhere" }
    $installPath = & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $installPath) { throw 'No Visual Studio with the x86/x64 VC tools was found.' }
    $vcvars = Join-Path $installPath 'VC\Auxiliary\Build\vcvars64.bat'
    if (-not (Test-Path -LiteralPath $vcvars)) { throw "vcvars64.bat not found at $vcvars" }
    Write-Host "Importing VC x64 environment from $vcvars"
    cmd /c " `"$vcvars`" >nul && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') {
            Set-Item -LiteralPath ("Env:" + $matches[1]) -Value $matches[2]
        }
    }
    foreach ($tool in 'cl.exe', 'lib.exe') {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            throw "$tool was not found on PATH after importing vcvars64.bat"
        }
    }
}

function Find-CMake {
    $command = Get-Command cmake.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $installation = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($installation) {
            $bundled = Join-Path $installation 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
            if (Test-Path -LiteralPath $bundled) { return $bundled }
        }
    }
    throw 'cmake.exe was not found. Install the Visual Studio C++ CMake component or add cmake to PATH.'
}

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][AllowEmptyCollection()][string[]]$Arguments,
        [string]$FailureMessage = 'Native command failed.'
    )
    # Drop null/empty entries: callers sometimes build the argument array from
    # optional parameters (e.g. an unset -ExtraInclude), and an empty element
    # would fail string[] parameter binding or be passed as a bogus argument.
    $Arguments = @($Arguments | Where-Object { $null -ne $_ -and "$_".Length -gt 0 })
    # Run a native tool (cmake, cl, lib, msbuild) with stdout and stderr merged
    # into a single temp file at the shell level and judge success solely from
    # the exit code. Two pitfalls are deliberately avoided:
    #   1. Under $ErrorActionPreference='Stop', Windows PowerShell turns the
    #      first native stderr line into a terminating NativeCommandError even
    #      when the process exits 0 (CMake policy/deprecation warnings trigger
    #      this on CMake 3.x and 4.x). Setting Continue around the call makes
    #      those non-terminating; pwsh 7 (the CI shell) does not raise them at
    #      all.
    #   2. Do NOT use Start-Process -RedirectStandardOutput/-RedirectStandardError
    #      here. On a headless windows-2022 runner MSBuild spawns parallel
    #      cl.exe children and the redirected pipes are not drained fast enough,
    #      so the build blocks until the job times out (observed for dyncall and
    #      asmjit). A file redirect hands every child a writable file handle
    #      with no pipe back-pressure.
    # The log is echoed via Write-Host so it never pollutes a caller's success
    # stream / return value.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $log = [IO.Path]::GetTempFileName()
    $code = 0
    try {
        & $FilePath @Arguments > $log 2>&1
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previous
    }
    Get-Content -LiteralPath $log | ForEach-Object { Write-Host $_ }
    Remove-Item -LiteralPath $log -Force -ErrorAction SilentlyContinue
    if ($code -ne 0) { throw "$FailureMessage (exit code $code)." }
}
