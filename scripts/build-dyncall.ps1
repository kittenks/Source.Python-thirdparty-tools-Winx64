[CmdletBinding()]
param(
    # Path to a dyncall source tree that ships the top-level CMake build.
    [Parameter(Mandatory = $true)][string]$Source,
    [string]$OutputDirectory = '',
    [string]$WorkDirectory = ''
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$src = [IO.Path]::GetFullPath($Source)
if (-not (Test-Path -LiteralPath (Join-Path $src 'CMakeLists.txt'))) {
    throw "dyncall source at '$src' has no top-level CMakeLists.txt. Use a dyncall ref/tag that ships the CMake build (the Nmakefile fallback is not implemented here)."
}

$root = Get-ToolsRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root 'artifacts\dyncall-win64' }
if (-not $WorkDirectory) { $WorkDirectory = Join-Path $root '_build\dyncall' }
New-CleanDirectory $WorkDirectory | Out-Null
$out = New-CleanDirectory $OutputDirectory

$cmake = Find-CMake
# No -G: let CMake pick the newest installed Visual Studio generator (VS2022 on
# windows-2022, newer on future images) and force the x64 platform with -A; this
# also lets the script run on a machine that only has a newer Visual Studio.
# dyncall 1.1 declares cmake_minimum_required(VERSION 2.6); CMake >= 4 refuses
# that, so pin the oldest policy version (CMake's own workaround). CMP0091 must
# be forced NEW because that old minimum leaves it OLD, otherwise
# CMAKE_MSVC_RUNTIME_LIBRARY is ignored and the static /MT CRT is not applied.
$configureArgs = @(
    '-S', $src,
    '-B', $WorkDirectory,
    '-A', 'x64',
    '-DCMAKE_POLICY_VERSION_MINIMUM=3.5',
    '-DCMAKE_POLICY_DEFAULT_CMP0091=NEW',
    '-DLANG_CXX=OFF',
    '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded'
)
Invoke-Native -FilePath $cmake -Arguments $configureArgs -FailureMessage 'dyncall CMake configure failed.'
Invoke-Native -FilePath $cmake -Arguments @('--build', $WorkDirectory, '--config', 'Release', '--parallel', '2') -FailureMessage 'dyncall CMake build failed.'

# CMake target name -> the file name Source.Python vendors under
# thirdparty/dyncall/lib/win64 (which carries the Unix "lib" prefix).
$pairs = [ordered]@{
    'dyncall_s'     = 'libdyncall_s.lib'
    'dyncallback_s' = 'libdyncallback_s.lib'
    'dynload_s'     = 'libdynload_s.lib'
}
$collected = [ordered]@{}
foreach ($target in $pairs.Keys) {
    $found = Get-ChildItem -LiteralPath $WorkDirectory -Recurse -Filter '*.lib' -File |
        Where-Object { $_.Name -like "*$target.lib" -and $_.Name -notmatch 'test|sample|example' } |
        Sort-Object Length -Descending | Select-Object -First 1
    if (-not $found) { throw "dyncall static target '$target' was not found in the build tree." }
    $dest = Join-Path $out $pairs[$target]
    Copy-Item -LiteralPath $found.FullName -Destination $dest -Force
    $collected[$pairs[$target]] = $found.Name
    Write-Host ("{0} <- {1} ({2:N0} bytes)" -f $pairs[$target], $found.Name, $found.Length)
}

New-Sha256Manifest -Directory $out -ManifestPath (Join-Path $out 'SHA256SUMS.txt')
[ordered]@{
    kind = 'dyncall-win64'
    source = 'dyncall 1.1 official release tarball (https://dyncall.org/r1.1/dyncall-1.1.tar.gz; hg tag r1.1 / changeset 2f28f26c72a7; pinned in manifests/versions.json)'
    source_path = $src
    cmake = 'auto Visual Studio generator (-A x64); -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_POLICY_DEFAULT_CMP0091=NEW -DLANG_CXX=OFF -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded (static /MT)'
    crt = '/MT'
    outputs = $collected
    built_at_utc = [DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $out 'build-info.json') -Encoding UTF8
Write-Host "dyncall artifact ready at $out"
