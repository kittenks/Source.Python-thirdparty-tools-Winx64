# ---------------------------------------------------------------------------
# Compare the exported symbols of two static libraries properly.
#
# The first attempt used findstr with a regex anchored at the start of the line,
# but dumpbin /exports indents every symbol row, so the real symbols were all
# filtered out and only the "Dump of file ..." header survived. That produced a
# meaningless "1 missing symbol" which was actually a filename. This parses the
# rows structurally instead of by pattern on the whole line.
#
# Usage: compare-exports.ps1 -A <lib> -B <lib> [-LabelA x86-32] [-LabelB x86-64]
# ---------------------------------------------------------------------------
param(
    [Parameter(Mandatory = $true)][string]$A,
    [Parameter(Mandatory = $true)][string]$B,
    [string]$LabelA = 'A',
    [string]$LabelB = 'B'
)

$ErrorActionPreference = 'Stop'

function Get-Exports([string]$lib) {
    $dump = & dumpbin /nologo /exports $lib 2>&1
    if ($LASTEXITCODE -ne 0) { throw "dumpbin failed on $lib" }
    $set = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($line in $dump) {
        # A symbol row is:  <ordinal> <hint> <RVA in hex> <mangled name>
        # The header row is "ordinal hint RVA name" and contains no leading number.
        $m = [regex]::Match($line, '^\s+(\d+)\s+(\d+)\s+([0-9A-Fa-f]{4,})\s+(\S.*)$')
        if ($m.Success) { [void]$set.Add($m.Groups[4].Value.Trim()) }
    }
    return $set
}

# dumpbin must be on PATH; the caller is expected to have run VsDevCmd.
$ea = Get-Exports $A
$eb = Get-Exports $B

Write-Output ("  {0,-10} {1,-46} {2,6} symbols" -f $LabelA, (Split-Path $A -Leaf), $ea.Count)
Write-Output ("  {0,-10} {1,-46} {2,6} symbols" -f $LabelB, (Split-Path $B -Leaf), $eb.Count)

$onlyA = @($ea | Where-Object { -not $eb.Contains($_) } | Sort-Object)
$onlyB = @($eb | Where-Object { -not $ea.Contains($_) } | Sort-Object)

Write-Output ""
Write-Output ("  in {0} but not {1}: {2}" -f $LabelA, $LabelB, $onlyA.Count)
foreach ($s in ($onlyA | Select-Object -First 25)) { Write-Output ("    - $s") }
if ($onlyA.Count -gt 25) { Write-Output ("    ... and $($onlyA.Count - 25) more") }

Write-Output ""
Write-Output ("  in {0} but not {1}: {2}" -f $LabelB, $LabelA, $onlyB.Count)
foreach ($s in ($onlyB | Select-Object -First 25)) { Write-Output ("    + $s") }
if ($onlyB.Count -gt 25) { Write-Output ("    ... and $($onlyB.Count - 25) more") }

Write-Output ""
if ($ea.Count -eq 0 -or $eb.Count -eq 0) {
    Write-Output "  VERDICT: INVALID - one side parsed to zero symbols, so the comparison proves nothing"
    exit 2
}
if ($onlyA.Count -eq 0) {
    Write-Output ("  VERDICT: every symbol {0} exports is present in {1}" -f $LabelA, $LabelB)
} else {
    Write-Output ("  VERDICT: {0} exports {1} symbol(s) that {2} does not - investigate before trusting this build" -f $LabelA, $onlyA.Count, $LabelB)
    exit 1
}
