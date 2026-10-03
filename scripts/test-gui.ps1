param([string]$Executable, [string]$Report)
$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
if (-not $Executable) { $Executable = Join-Path $repository 'artifacts/win-x64/DriveWitness.exe' }
if (-not $Report) { $Report = Join-Path $repository 'artifacts/GUI_CSHARP_REPORT.json' }
$Executable = [IO.Path]::GetFullPath($Executable)
$Report = [IO.Path]::GetFullPath($Report)
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Report) | Out-Null
$testProcess = [Diagnostics.Process]::new()
$testProcess.StartInfo.FileName = $Executable
$testProcess.StartInfo.UseShellExecute = $false
$testProcess.StartInfo.CreateNoWindow = $true
$testProcess.StartInfo.Arguments = '--self-test "' + $Report + '"'
try {
    $testProcess.Start() | Out-Null
    if (-not $testProcess.WaitForExit(60000)) { $testProcess.Kill(); throw 'GUI acceptance test timed out.' }
    if ($testProcess.ExitCode -ne 0) { throw "GUI test failed; inspect $Report" }
    Get-Content -LiteralPath $Report
} finally { $testProcess.Dispose() }
