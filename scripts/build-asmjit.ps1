[CmdletBinding()]
param(
    # Path to an AsmJit 1.14.0 source tree (git tag 1.14.0).
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
# Static CRT (/MT) via CMP0091; static AsmJit; no test executables.
& $cmake -S $src -B $WorkDirectory -G 'Visual Studio 17 2022' -A x64 `
    -DASMJIT_STATIC=TRUE `
    -DASMJIT_BUILD_TEST=FALSE `
    -DCMAKE_POLICY_DEFAULT_CMP0091=NEW `
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded
if ($LASTEXITCODE -ne 0) { throw 'AsmJit CMake configure failed.' }

& $cmake --build $WorkDirectory --config Release --parallel 2
if ($LASTEXITCODE -ne 0) { throw 'AsmJit CMake build failed.' }

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
    source = 'asmjit/asmjit git tag 1.14.0'
    source_path = $src
    cmake = '-DASMJIT_STATIC=TRUE -DASMJIT_BUILD_TEST=FALSE -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded'
    crt = '/MT'
    upstream_library = $built.Name
    outputs = @('AsmJit.lib')
    built_at_utc = [DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $out 'build-info.json') -Encoding UTF8
Write-Host "AsmJit artifact ready at $out"
