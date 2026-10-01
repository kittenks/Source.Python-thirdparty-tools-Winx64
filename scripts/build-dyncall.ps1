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
& $cmake -S $src -B $WorkDirectory -G 'Visual Studio 17 2022' -A x64 `
    -DCMAKE_POLICY_DEFAULT_CMP0091=NEW `
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded
if ($LASTEXITCODE -ne 0) { throw 'dyncall CMake configure failed.' }

& $cmake --build $WorkDirectory --config Release --parallel 2
if ($LASTEXITCODE -ne 0) { throw 'dyncall CMake build failed.' }

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
    source = 'dyncall/dyncall (pinned in manifests/versions.json)'
    source_path = $src
    cmake = '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded (static /MT)'
    crt = '/MT'
    outputs = $collected
    built_at_utc = [DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $out 'build-info.json') -Encoding UTF8
Write-Host "dyncall artifact ready at $out"
