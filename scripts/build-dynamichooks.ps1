[CmdletBinding()]
param(
    # Path to src/thirdparty in a checked-out Source.Python spWinx64 tree.
    # The DynamicHooks/HDE64 sources carry the Windows x86-64 fixes, so they
    # come from kittenks/Source.Python@spWinx64 - never from upstream DynamicHooks.
    [Parameter(Mandatory = $true)][string]$ThirdPartyDir,
    [string]$OutputDirectory = '',
    [string]$WorkDirectory = ''
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$tp = [IO.Path]::GetFullPath($ThirdPartyDir)
$srcRoot = [IO.Path]::GetFullPath((Join-Path $tp '..'))
$dh = Join-Path $tp 'DynamicHooks'
$hde = Join-Path $tp 'HDE64'
$asmInclude = Join-Path $tp 'AsmJit\include'

$required = @(
    (Join-Path $dh 'src\hook_x64.cpp'),
    (Join-Path $dh 'src\manager.cpp'),
    (Join-Path $dh 'src\registers.cpp'),
    (Join-Path $dh 'src\x64MsWin64.cpp'),
    (Join-Path $hde 'hde64.c'),
    # Vendored AsmJit uses the flat header layout (include/x86.h), not the
    # upstream asmjit/x86.h nested one. hook_x64.cpp does #include "x86.h".
    (Join-Path $asmInclude 'x86.h')
)
foreach ($need in $required) {
    if (-not (Test-Path -LiteralPath $need)) { throw "Missing DynamicHooks source: $need" }
}

$root = Get-ToolsRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root 'artifacts\dynamichooks-win64' }
if (-not $WorkDirectory) { $WorkDirectory = Join-Path $root '_build\dynamichooks' }
New-CleanDirectory $WorkDirectory | Out-Null
$out = New-CleanDirectory $OutputDirectory

Import-VcToolsX64

# Mirror the include dirs CMake uses when it compiles these same translation
# units into core on x86-64 (see src/makefiles/win32/win32.base.cmake): the src/
# root (for "thirdparty/HDE64/hde64.h"), DynamicHooks/include/conventions (for
# x64MsWin64.h), the HDE64 root itself, and the flat AsmJit include dir.
$include = @(
    "/I$dh\include",
    "/I$dh\include\conventions",
    "/I$srcRoot",
    "/I$hde",
    "/I$asmInclude"
)
$defines = @('/DDYNAMICHOOKS_X86_64', '/DASMJIT_STATIC', '/DWIN32', '/D_WIN32', '/D_WIN64', '/DNDEBUG')
$cFlags = @('/c', '/MT', '/O2', '/W3', '/nologo')
$cxxFlags = @('/c', '/MT', '/O2', '/EHsc', '/std:c++17', '/W3', '/wd4005', '/nologo')

function Invoke-Cl {
    param([string]$SourceFile, [string]$ObjectFile, [string[]]$Flags)
    & cl.exe @Flags @defines @include "$SourceFile" "/Fo$ObjectFile"
    if ($LASTEXITCODE -ne 0) { throw "cl.exe failed for $SourceFile (exit $LASTEXITCODE)" }
    if (-not (Test-Path -LiteralPath $ObjectFile)) { throw "Object file was not produced: $ObjectFile" }
}

$objects = @()
$hdeObj = Join-Path $WorkDirectory 'hde64.obj'
Invoke-Cl -SourceFile (Join-Path $hde 'hde64.c') -ObjectFile $hdeObj -Flags $cFlags
$objects += $hdeObj

foreach ($unit in 'hook_x64.cpp', 'manager.cpp', 'registers.cpp', 'x64MsWin64.cpp') {
    $obj = Join-Path $WorkDirectory ($unit -replace '\.cpp$', '.obj')
    Invoke-Cl -SourceFile (Join-Path $dh "src\$unit") -ObjectFile $obj -Flags $cxxFlags
    $objects += $obj
}

$libOut = Join-Path $out 'DynamicHooks.lib'
& lib.exe /NOLOGO "/OUT:$libOut" $objects
if ($LASTEXITCODE -ne 0) { throw "lib.exe failed (exit $LASTEXITCODE)" }
if (-not (Test-Path -LiteralPath $libOut)) { throw 'DynamicHooks.lib was not produced.' }
$size = (Get-Item -LiteralPath $libOut).Length
if ($size -lt 100000) { throw "DynamicHooks.lib is implausibly small ($size bytes)." }
Write-Host ("DynamicHooks.lib built: {0:N0} bytes from {1} objects" -f $size, $objects.Count)

New-Sha256Manifest -Directory $out -ManifestPath (Join-Path $out 'SHA256SUMS.txt')
[ordered]@{
    kind = 'dynamichooks-win64'
    source = 'kittenks/Source.Python@spWinx64 src/thirdparty/{DynamicHooks,HDE64,AsmJit}'
    defines = @('DYNAMICHOOKS_X86_64', 'ASMJIT_STATIC', 'WIN32', '_WIN32', '_WIN64', 'NDEBUG')
    crt = '/MT'
    objects = @($objects | ForEach-Object { Split-Path $_ -Leaf })
    outputs = @('DynamicHooks.lib')
    built_at_utc = [DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $out 'build-info.json') -Encoding UTF8
Write-Host "DynamicHooks artifact ready at $out"
