[CmdletBinding()]
param(
    # Path to the pinned AsmJit source tree (commit in manifests/versions.json;
    # upstream has no tags and the pin selects the last ABI namespace v1_14).
    [Parameter(Mandatory = $true)][string]$Source,
    [string]$OutputDirectory = '',
    [string]$WorkDirectory = ''
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$src = [IO.Path]::GetFullPath($Source)
if (-not (Test-Path -LiteralPath (Join-Path $src 'CMakeLists.txt'))) {
    throw "AsmJit source is missing CMakeLists.txt: $src"
}

$root = Get-ToolsRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root 'artifacts\asmjit-win64' }
if (-not $WorkDirectory) { $WorkDirectory = Join-Path $root '_build\asmjit' }
New-CleanDirectory $WorkDirectory | Out-Null
$out = New-CleanDirectory $OutputDirectory

$cmake = Find-CMake
# No -G: pick the newest installed Visual Studio generator (VS2022 on
# windows-2022, newer on future images) and force x64 with -A. Static AsmJit
# with the static /MT CRT. The pinned commit's CMake already defaults CMP0091 to
# NEW and builds no tests for the static target, so the (unused in this
# revision) ASMJIT_BUILD_TEST / CMP0091 overrides are deliberately not passed.
$configureArgs = @(
    '-S', $src,
    '-B', $WorkDirectory,
    '-A', 'x64',
    '-DASMJIT_STATIC=TRUE',
    '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded'
)
Invoke-Native -FilePath $cmake -Arguments $configureArgs -FailureMessage 'AsmJit CMake configure failed.'
Invoke-Native -FilePath $cmake -Arguments @('--build', $WorkDirectory, '--config', 'Release', '--parallel', '2') -FailureMessage 'AsmJit CMake build failed.'

$built = Get-ChildItem -LiteralPath $WorkDirectory -Recurse -Filter 'asmjit*.lib' -File |
    Where-Object { $_.Name -notmatch 'test' } |
    Sort-Object Length -Descending | Select-Object -First 1
if (-not $built) { throw 'No static AsmJit library was found in the build tree.' }

$dest = Join-Path $out 'AsmJit.lib'
Copy-Item -LiteralPath $built.FullName -Destination $dest -Force
Write-Host ("Copied {0} ({1:N0} bytes) -> AsmJit.lib" -f $built.Name, $built.Length)

New-Sha256Manifest -Directory $out -ManifestPath (Join-Path $out 'SHA256SUMS.txt')
[ordered]@{
    kind = 'asmjit-win64'
    source = 'asmjit/asmjit pinned commit 9eb6edbf711ceb25346ee40bae68b40a4505cdf5 (last master revision with ASMJIT_ABI_NAMESPACE v1_14; upstream has no git tags)'
    source_path = $src
    cmake = 'auto Visual Studio generator (-A x64); -DASMJIT_STATIC=TRUE -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded (static /MT)'
    crt = '/MT'
    upstream_library = $built.Name
    outputs = @('AsmJit.lib')
    built_at_utc = [DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $out 'build-info.json') -Encoding UTF8
Write-Host "AsmJit artifact ready at $out"
