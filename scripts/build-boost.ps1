[CmdletBinding()]
param(
    # Path to an extracted Boost 1.87.0 source tree (the directory that
    # contains bootstrap.bat and boost\python.hpp).
    [Parameter(Mandatory = $true)][string]$BoostSource,
    # Path to the CPython 3.13 headers (Python.h). On CI this is
    # "$env:pythonLocation\include" from actions/setup-python x64 3.13.
    [Parameter(Mandatory = $true)][string]$PythonInclude,
    [string]$OutputDirectory = '',
    [string]$WorkDirectory = ''
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$boost = [IO.Path]::GetFullPath($BoostSource)
$pythonInclude = [IO.Path]::GetFullPath($PythonInclude)
foreach ($need in @(
        (Join-Path $boost 'boost\python.hpp'),
        (Join-Path $boost 'boost\atomic\atomic_ref.hpp'),
        (Join-Path $pythonInclude 'Python.h'))) {
    if (-not (Test-Path -LiteralPath $need)) { throw "Required header missing: $need" }
}

$root = Get-ToolsRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root 'artifacts\boost-win64' }
if (-not $WorkDirectory) { $WorkDirectory = Join-Path $root '_build\boost' }
New-CleanDirectory $WorkDirectory | Out-Null
$out = New-CleanDirectory $OutputDirectory

Import-VcToolsX64

# Mirrors the project's Release (/MT, /O2) settings. b2's MSVC toolset
# provisioning is bypassed: these libraries are plain translation units, so
# cl.exe/lib.exe are invoked directly (the configuration proven locally).
function Compile-TranslationUnits {
    param(
        [string[]]$Sources,
        [string[]]$ExtraDefines,
        [string[]]$ExtraInclude,
        [string]$ObjectDirectory,
        [switch]$MultiProcess
    )
    New-CleanDirectory $ObjectDirectory | Out-Null
    $flags = @('/nologo', '/c', '/MT', '/EHsc', '/O2', '/bigobj')
    if ($MultiProcess) { $flags += '/MP' }
    $flags += @('/DWIN32', '/D_WINDOWS', '/DNDEBUG', '/DBOOST_ALL_NO_LIB',
        '/D_HAS_EXCEPTIONS=1', '/D_SCL_SECURE_NO_WARNINGS', '/D_CRT_SECURE_NO_WARNINGS', '/wd4996')
    if ($ExtraDefines) { $flags += $ExtraDefines }
    $flags += "/I$boost"
    if ($ExtraInclude) { $flags += $ExtraInclude }

    $objects = @()
    foreach ($source in $Sources) {
        $object = Join-Path $ObjectDirectory (([IO.Path]::GetFileNameWithoutExtension($source)) + '.obj')
        # Go through Invoke-Native: it echoes compiler output with Write-Host,
        # which does NOT enter this function's success stream. A bare cl.exe call
        # prints the source file name ("error_code.cpp"); that string would
        # otherwise leak into the return value alongside the .obj paths and be
        # handed to lib.exe, causing LNK1181 "cannot open input file
        # 'error_code.cpp'". Invoke-Native also handles cl stderr warnings and
        # the non-zero exit case.
        Invoke-Native -FilePath 'cl.exe' -Arguments ($flags + @("$source", "/Fo$object")) `
            -FailureMessage "cl.exe failed for $source"
        if (-not (Test-Path -LiteralPath $object)) { throw "Object not produced: $object" }
        $objects += $object
    }
    return ,$objects
}

function New-StaticArchive {
    param([string]$LibraryName, [string[]]$Objects)
    $dest = Join-Path $out $LibraryName
    Invoke-Native -FilePath 'lib.exe' -Arguments (@('/NOLOGO', "/OUT:$dest") + @($Objects)) `
        -FailureMessage "lib.exe failed for $LibraryName"
    if (-not (Test-Path -LiteralPath $dest)) { throw "$LibraryName was not produced." }
    Write-Host ("{0} built from {1} objects ({2:N0} bytes)" -f $LibraryName, $Objects.Count, (Get-Item $dest).Length)
}

# --- Boost.System (1 translation unit) ---
$systemObjects = Compile-TranslationUnits `
    -Sources @(Join-Path $boost 'libs\system\src\error_code.cpp') `
    -ExtraDefines @('/DBOOST_SYSTEM_STATIC_LINK') `
    -ObjectDirectory (Join-Path $WorkDirectory 'system')
New-StaticArchive 'libboost_system-vc143-mt-s-x64-1_87.lib' $systemObjects

# --- Boost.Filesystem (10 translation units) ---
$fsSources = @(Get-ChildItem -LiteralPath (Join-Path $boost 'libs\filesystem\src') -Filter '*.cpp' -File |
        Sort-Object FullName | ForEach-Object { $_.FullName })
if ($fsSources.Count -ne 10) { throw "Expected 10 Boost.Filesystem TUs, found $($fsSources.Count)." }
$fsObjects = Compile-TranslationUnits `
    -Sources $fsSources `
    -ExtraDefines @('/DBOOST_SYSTEM_STATIC_LINK', '/DBOOST_FILESYSTEM_STATIC_LINK', '/DBOOST_FILESYSTEM_NO_CXX20_ATOMIC_REF') `
    -ObjectDirectory (Join-Path $WorkDirectory 'filesystem')
New-StaticArchive 'libboost_filesystem-vc143-mt-s-x64-1_87.lib' $fsObjects

# --- Boost.Python 3.13 (27 translation units; numpy is a separate library and is excluded) ---
$pythonSources = @(Get-ChildItem -LiteralPath (Join-Path $boost 'libs\python\src') -Recurse -Filter '*.cpp' -File |
        Where-Object { $_.FullName -notmatch '\\numpy\\' } |
        Sort-Object FullName | ForEach-Object { $_.FullName })
if ($pythonSources.Count -ne 27) { throw "Expected 27 Boost.Python TUs (excluding numpy), found $($pythonSources.Count)." }
$pythonObjects = Compile-TranslationUnits `
    -Sources $pythonSources `
    -ExtraDefines @('/DBOOST_PYTHON_STATIC_LIB', '/DBOOST_PYTHON_SOURCE') `
    -ExtraInclude @("/I$pythonInclude") `
    -ObjectDirectory (Join-Path $WorkDirectory 'python') `
    -MultiProcess
New-StaticArchive 'libboost_python313-vc143-mt-s-x64-1_87.lib' $pythonObjects

New-Sha256Manifest -Directory $out -ManifestPath (Join-Path $out 'SHA256SUMS.txt')
[ordered]@{
    kind = 'boost-win64'
    version = '1.87.0'
    source_path = $boost
    python_include = $pythonInclude
    crt = '/MT'
    translation_units = [ordered]@{ system = 1; filesystem = 10; python313 = 27 }
    outputs = @(
        'libboost_system-vc143-mt-s-x64-1_87.lib',
        'libboost_filesystem-vc143-mt-s-x64-1_87.lib',
        'libboost_python313-vc143-mt-s-x64-1_87.lib'
    )
    built_at_utc = [DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'build-info.json') -Encoding UTF8
Write-Host "Boost artifact ready at $out"
