[CmdletBinding(SupportsShouldProcess = $true)]
param()
$ErrorActionPreference = 'Stop'
$bundle = [IO.Path]::GetFullPath($PSScriptRoot)
if (-not (Test-Path -LiteralPath (Join-Path $bundle 'DriveWitness.exe'))) { throw 'Run Install.ps1 from the extracted Windows release bundle.' }
$programs = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Programs'))
$install = [IO.Path]::GetFullPath((Join-Path $programs 'DriveWitness'))
if (-not $install.StartsWith($programs + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid installation path.' }
if ($bundle.Equals($install, [StringComparison]::OrdinalIgnoreCase)) { throw 'This copy is already installed.' }
$marker = Join-Path $install 'drivewitness-install.json'
if ((Test-Path -LiteralPath $install) -and -not (Test-Path -LiteralPath $marker) -and (Get-ChildItem -LiteralPath $install -Force | Select-Object -First 1)) { throw 'The destination contains files that were not installed by DriveWitness.' }
if (Test-Path -LiteralPath $install) {
    if (Get-ChildItem -LiteralPath $install -Recurse -Attributes ReparsePoint | Select-Object -First 1) { throw 'Installation cannot overwrite junctions or symbolic links.' }
    $running = Get-Process -Name 'DriveWitness','drivewitness-cli' -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($install + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) }
    if ($running) { throw 'Close the installed DriveWitness GUI and CLI before updating.' }
}
if (-not $PSCmdlet.ShouldProcess($install, 'Install DriveWitness and create current-user Start Menu shortcuts')) { return }
New-Item -ItemType Directory -Path $install -Force | Out-Null
if ((Get-Item -LiteralPath $install).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Installation directory cannot be a junction or symbolic link.' }
Get-ChildItem -LiteralPath $bundle -Force | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $install -Recurse -Force }
$installedFiles = @(Get-ChildItem -LiteralPath $bundle -File -Recurse | ForEach-Object { @{ path = $_.FullName.Substring($bundle.Length + 1); sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash } })
@{ product = 'DriveWitness'; install_path = $install; installed_utc = [DateTime]::UtcNow.ToString('o'); files = $installedFiles } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $marker -Encoding UTF8
$shortcutDirectory = Join-Path ([Environment]::GetFolderPath('Programs')) 'DriveWitness'
New-Item -ItemType Directory -Path $shortcutDirectory -Force | Out-Null
$shortcutShell = New-Object -ComObject WScript.Shell
$shortcut = $shortcutShell.CreateShortcut((Join-Path $shortcutDirectory 'DriveWitness.lnk'))
$shortcut.TargetPath = Join-Path $install 'DriveWitness.exe'; $shortcut.WorkingDirectory = $install; $shortcut.IconLocation = "$($shortcut.TargetPath),0"; $shortcut.Save()
$remove = $shortcutShell.CreateShortcut((Join-Path $shortcutDirectory 'Uninstall DriveWitness.lnk'))
$remove.TargetPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'; $remove.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $install 'Uninstall.ps1') + '"'; $remove.IconLocation = "$($shortcut.TargetPath),0"; $remove.Save()
Write-Output "Installed: $install"
Write-Output 'Start Menu shortcuts created. Evidence databases and user settings are stored separately.'
