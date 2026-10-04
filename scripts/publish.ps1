param([ValidateSet('win-x64', 'win-arm64')][string]$Runtime = 'win-x64', [switch]$SkipTests)
$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
if (-not $SkipTests) { & (Join-Path $PSScriptRoot 'build.ps1') }
$output = [IO.Path]::GetFullPath((Join-Path $repository "artifacts/$Runtime"))
if (-not $output.StartsWith([IO.Path]::GetFullPath($repository) + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Publish path is outside the workspace.' }
New-Item -ItemType Directory -Force -Path $output | Out-Null
foreach ($project in @('src/DriveWitness.App/DriveWitness.App.csproj', 'src/DriveWitness.Cli/DriveWitness.Cli.csproj')) {
    dotnet publish (Join-Path $repository $project) -c Release -r $Runtime --self-contained true -p:PublishSingleFile=false -p:PublishTrimmed=false -o $output
    if ($LASTEXITCODE -ne 0) { throw "Publish failed: $project" }
}
foreach ($name in @('README.md', 'LICENSE', 'NOTICE', 'STORE_EULA.txt', 'PRIVACY.md', 'STORE_DISTRIBUTION.md', 'EVIDENCE_FORMAT.md', 'THIRD_PARTY_NOTICES.md', 'DEVELOPMENT_NOTES.md', 'MODERNIZATION_REPORT.md', 'BUG_PERFORMANCE_AUDIT.md', 'CSHARP_PERFORMANCE_REPORT.md', 'CSHARP_PERFORMANCE_REPORT.json', 'CSHARP_GUI_REPORT.json')) {
    if (Test-Path -LiteralPath (Join-Path $repository $name)) { Copy-Item -LiteralPath (Join-Path $repository $name) -Destination $output }
}
if (Test-Path -LiteralPath (Join-Path $repository 'docs')) { Copy-Item -LiteralPath (Join-Path $repository 'docs') -Destination $output -Recurse -Force }
if (Test-Path -LiteralPath (Join-Path $repository 'licenses')) { Copy-Item -LiteralPath (Join-Path $repository 'licenses') -Destination $output -Recurse -Force }
foreach ($name in @('Install.ps1', 'Uninstall.ps1')) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $output -Force }
$releaseVersion = ([xml](Get-Content -LiteralPath (Join-Path $repository 'Directory.Build.props') -Raw)).Project.PropertyGroup.Version
$archive = Join-Path $repository "artifacts/DriveWitness-$releaseVersion-$Runtime.zip"
Compress-Archive -LiteralPath $output -DestinationPath $archive -Force
Write-Output "GUI: $(Join-Path $output 'DriveWitness.exe')"
Write-Output "CLI: $(Join-Path $output 'drivewitness-cli.exe')"
Write-Output "ZIP: $archive"
