[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param()
$ErrorActionPreference = 'Stop'
$install = [IO.Path]::GetFullPath($PSScriptRoot)
$programs = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Programs'))
$expected = [IO.Path]::GetFullPath((Join-Path $programs 'DriveWitness'))
if (-not $install.Equals($expected, [StringComparison]::OrdinalIgnoreCase)) { throw 'Uninstall only runs from the current-user DriveWitness installation.' }
$marker = Get-Content -LiteralPath (Join-Path $install 'drivewitness-install.json') -Raw | ConvertFrom-Json
if ($marker.product -ne 'DriveWitness' -or -not $install.Equals($marker.install_path, [StringComparison]::OrdinalIgnoreCase)) { throw 'Installation marker does not match this directory.' }
if (-not $marker.files) { throw 'The installation file manifest is missing.' }
if ((Get-Item -LiteralPath $install).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Installation directory cannot be a junction or symbolic link.' }
$running = Get-Process -Name 'DriveWitness','drivewitness-cli' -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($install + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) }
if ($running) { throw 'Close the installed DriveWitness GUI and CLI before uninstalling.' }
if (Get-ChildItem -LiteralPath $install -Recurse -Attributes ReparsePoint | Select-Object -First 1) { throw 'Move junctions or symbolic links out of the installation before uninstalling.' }
if (Get-ChildItem -LiteralPath $install -Recurse -File -Filter '*.db*' | Select-Object -First 1) { throw 'Evidence or review databases are stored in the installation directory. Move them before uninstalling.' }
$knownFiles = @{}
foreach ($file in $marker.files) {
    $path = [IO.Path]::GetFullPath((Join-Path $install $file.path))
    if (-not $path.StartsWith($install + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid installation file manifest path.' }
    $knownFiles[$path] = $file.sha256
}
Get-ChildItem -LiteralPath $install -File -Recurse | ForEach-Object {
    if ($_.Name -eq 'drivewitness-install.json' -and $_.DirectoryName -eq $install) { return }
    if (-not $knownFiles.ContainsKey($_.FullName) -or (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash -ne $knownFiles[$_.FullName]) { throw "Retained user or modified file: $($_.FullName). Move it before uninstalling." }
}
if (-not $PSCmdlet.ShouldProcess($install, 'Remove DriveWitness application files and Start Menu shortcuts; keep user settings and external evidence')) { return }
$shortcutDirectory = [IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath('Programs')) 'DriveWitness'))
$shortcutParent = [IO.Path]::GetFullPath([Environment]::GetFolderPath('Programs'))
if (-not $shortcutDirectory.StartsWith($shortcutParent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid shortcut path.' }
foreach ($name in @('DriveWitness.lnk', 'Uninstall DriveWitness.lnk')) { $path = Join-Path $shortcutDirectory $name; if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force } }
if ((Test-Path -LiteralPath $shortcutDirectory) -and -not (Get-ChildItem -LiteralPath $shortcutDirectory -Force | Select-Object -First 1)) { Remove-Item -LiteralPath $shortcutDirectory }
Remove-Item -LiteralPath $install -Recurse -Force
Write-Output 'DriveWitness removed. User settings and evidence outside the installation directory were retained.'
