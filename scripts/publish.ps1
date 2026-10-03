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
foreach ($name in @('README.md', 'LICENSE', 'EVIDENCE_FORMAT.md', 'THIRD_PARTY_NOTICES.md', 'DEVELOPMENT_NOTES.md', 'CSHARP_PERFORMANCE_REPORT.md', 'CSHARP_PERFORMANCE_REPORT.json', 'CSHARP_GUI_REPORT.json')) {
    if (Test-Path -LiteralPath (Join-Path $repository $name)) { Copy-Item -LiteralPath (Join-Path $repository $name) -Destination $output }
}
if (Test-Path -LiteralPath (Join-Path $repository 'docs')) { Copy-Item -LiteralPath (Join-Path $repository 'docs') -Destination $output -Recurse -Force }
if (Test-Path -LiteralPath (Join-Path $repository 'licenses')) { Copy-Item -LiteralPath (Join-Path $repository 'licenses') -Destination $output -Recurse -Force }
$archive = Join-Path $repository "artifacts/DriveWitness-3.0.0-$Runtime.zip"
Compress-Archive -LiteralPath $output -DestinationPath $archive -Force
Write-Output "GUI: $(Join-Path $output 'DriveWitness.exe')"
Write-Output "CLI: $(Join-Path $output 'drivewitness-cli.exe')"
Write-Output "ZIP: $archive"
