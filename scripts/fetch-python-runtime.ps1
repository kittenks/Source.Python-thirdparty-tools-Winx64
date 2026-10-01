[CmdletBinding()]
param(
    [string]$RepositoryRoot = '',
    [string]$OutputDirectory = '',
    # Keep the embeddable stdlib zip / ._pth. Off by default: Source.Python
    # ships its own standard library, so only the native runtime is wanted.
    [switch]$KeepPthAndZip
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$root = if ($RepositoryRoot) { [IO.Path]::GetFullPath($RepositoryRoot) } else { Get-ToolsRoot }
$versions = Get-Versions -Root $root
$rt = $versions.python_runtime

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $root 'artifacts\python-runtime-win64'
}
$work = Join-Path $root '_build\python-runtime'
$zip = Join-Path $work ("python-{0}-embed-amd64.zip" -f $rt.version)
$extract = Join-Path $work 'extract'
$platRelative = $rt.package_layout.Replace('/', '\')   # Python3\plat-win
$plat = Join-Path $OutputDirectory $platRelative

New-CleanDirectory $work | Out-Null
New-CleanDirectory $extract | Out-Null
New-CleanDirectory $OutputDirectory | Out-Null

$zipSha = Download-CheckedFile -Url $rt.source_url -OutFile $zip -ExpectedSha256 $rt.expected_sha256
Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force

if (-not $KeepPthAndZip) {
    foreach ($name in $rt.drop_from_embeddable) {
        Remove-Item -LiteralPath (Join-Path $extract $name) -Force -ErrorAction SilentlyContinue
    }
}

# plat-win must contain native binaries only; it is replaced wholesale when
# packaging a Windows x86-64 game archive (the repo copy is the x86 set).
New-CleanDirectory $plat | Out-Null
$nativeFiles = Get-ChildItem -LiteralPath $extract -File |
    Where-Object { $_.Extension -in '.dll', '.pyd' } | Sort-Object Name
foreach ($file in $nativeFiles) {
    Assert-PeX64 -Path $file.FullName
    Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $plat $file.Name) -Force
}

# Keep the CPython license alongside (not inside plat-win) for compliance.
Get-ChildItem -LiteralPath $extract -File -Filter 'LICENSE*' -ErrorAction SilentlyContinue |
    Copy-Item -Destination $OutputDirectory -Force

$count = (Get-ChildItem -LiteralPath $plat -File).Count
Write-Host "Packaged $count PE-x86-64 runtime files into $plat"
New-Sha256Manifest -Directory $OutputDirectory -ManifestPath (Join-Path $OutputDirectory 'SHA256SUMS.txt')

$info = [ordered]@{
    kind = 'cpython-embeddable-win64'
    version = $rt.version
    source_url = $rt.source_url
    archive_sha256 = $zipSha
    package_layout = $rt.package_layout
    native_file_count = $count
    files = @(Get-ChildItem -LiteralPath $plat -File | Sort-Object Name | ForEach-Object { $_.Name })
    built_at_utc = [DateTime]::UtcNow.ToString('o')
}
$info | ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath (Join-Path $OutputDirectory 'runtime-info.json') -Encoding UTF8
Write-Host "Python runtime artifact ready at $OutputDirectory"
