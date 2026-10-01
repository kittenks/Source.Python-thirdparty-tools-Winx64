# ---------------------------------------------------------------------------
# Compare the DEFINED external symbols of two static libraries.
#
# Two earlier attempts were wrong, both in ways that would have produced a
# meaningless answer:
#
#   1. findstr with a regex anchored at the start of the line. dumpbin indents
#      every row, so every real symbol was filtered out and only the
#      "Dump of file ..." header survived, giving a fake "1 missing symbol"
#      that was a filename.
#
#   2. dumpbin /exports. That reports a DLL's export directory. A .lib is a
#      static library and keeps its symbols in the COFF symbol table, so
#      /exports returns only a section-size Summary and zero symbols.
#
# This uses dumpbin /symbols and keeps rows that are External and defined, which
# is the set a consumer can actually link against. Section names (".text$mn"),
# absolute symbols ("@comp.id") and internal linkage are excluded.
#
# Differences in both directions are reported rather than treated as failure,
# because an x86 and an x64 build of the same headers are not obliged to produce
# identical symbol sets. What matters is reported plainly so it can be judged.
# ---------------------------------------------------------------------------
param(
    [Parameter(Mandatory = $true)][string]$A,
    [Parameter(Mandatory = $true)][string]$B,
    [string]$LabelA = 'A',
    [string]$LabelB = 'B'
)

$ErrorActionPreference = 'Stop'

function Get-DefinedExternal([string]$lib) {
    $dump = & dumpbin /nologo /symbols $lib 2>&1
    if ($LASTEXITCODE -ne 0) { throw "dumpbin /symbols failed on $lib" }
    $set = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($line in $dump) {
        # <idx> <value> <section> <type> <storage> | <mangled> [ (<demangled>) ]
        $m = [regex]::Match(
            $line,
            '^\s*[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)\s+\S+\s+External\s+\|\s+(\S+)')
        if (-not $m.Success) { continue }
        $section = $m.Groups[1].Value
        $name    = $m.Groups[2].Value
        if ($section -eq 'UNDEF')  { continue }   # imported, not defined here
        if ($name.StartsWith('.'))  { continue }   # a section name
        if ($name.StartsWith('@'))  { continue }   # @comp.id / @feat.00 / @vol.md
        [void]$set.Add($name)
    }
    return $set
}

$ea = Get-DefinedExternal $A
$eb = Get-DefinedExternal $B

Write-Output ("  {0,-8} {1,-46} {2,6} defined external symbols" -f $LabelA, (Split-Path $A -Leaf), $ea.Count)
Write-Output ("  {0,-8} {1,-46} {2,6} defined external symbols" -f $LabelB, (Split-Path $B -Leaf), $eb.Count)

if ($ea.Count -eq 0 -or $eb.Count -eq 0) {
    Write-Output ""
    Write-Output "  VERDICT: INVALID - a side parsed to zero symbols, so this proves nothing"
    exit 2
}

$onlyA = @($ea | Where-Object { -not $eb.Contains($_) } | Sort-Object)
$onlyB = @($eb | Where-Object { -not $ea.Contains($_) } | Sort-Object)
$both  = $ea.Count - $onlyA.Count

Write-Output ("  shared: {0}" -f $both)
Write-Output ""
Write-Output ("  defined by {0} only: {1}" -f $LabelA, $onlyA.Count)
foreach ($s in ($onlyA | Select-Object -First 30)) { Write-Output ("    - $s") }
if ($onlyA.Count -gt 30) { Write-Output ("    ... and $($onlyA.Count - 30) more") }

Write-Output ""
Write-Output ("  defined by {0} only: {1}" -f $LabelB, $onlyB.Count)
foreach ($s in ($onlyB | Select-Object -First 30)) { Write-Output ("    + $s") }
if ($onlyB.Count -gt 30) { Write-Output ("    ... and $($onlyB.Count - 30) more") }

Write-Output ""
Write-Output ("  VERDICT: {0}" -f $(if ($onlyA.Count -eq 0) {
    "every defined external symbol in $LabelA is present in $LabelB"
} else {
    "$LabelA defines $($onlyA.Count) symbol(s) absent from $LabelB - listed above, judge each"
}))
