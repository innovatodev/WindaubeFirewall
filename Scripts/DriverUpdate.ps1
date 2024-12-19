$ErrorActionPreference = "Stop"

$OutDir = "$PSScriptRoot\..\Data\DriverFiles"
$Uri_Prefix = "https://updates.safing.io"

function Invoke-DownloadDriver {
    param ([string]$Version)

    $files = @(
        "portmaster-kext_v$Version.sys|portmaster-kext.sys",
        "portmaster-kext_v$Version.sys.sig|portmaster-kext.sig",
        "portmaster-kext_v$Version.pdb|portmaster-kext.pdb",
        "portmaster-kext_v$Version.pdb.sig|portmaster-kext.pdb.sig"
    )

    foreach ($file in $files) {
        $source, $dest = $file.Split("|")
        $fullDest = Join-Path $OutDir $dest
        Remove-Item -Path $fullDest -Force -ErrorAction SilentlyContinue
        Invoke-WebRequest -Uri "$Uri_Prefix/windows_amd64/kext/$source" -OutFile $fullDest
    }

    Set-Content -Path "$OutDir\portmaster-kext.sys.version" -Value ($Version -replace '-', '.')
}

try {
    # Get latest version
    Write-Host "Downloading beta.json"
    $jsonContent = Invoke-WebRequest -Uri "$Uri_Prefix/beta.json" | ConvertFrom-Json
    $jsonContent
    $latestVersion = $jsonContent.'windows_amd64/kext/portmaster-kext.sys'
    $latestVersion = $latestVersion -replace '\.', '-'
    Write-Host "Latest version: $latestVersion"

    # Check current version
    $versionFile = "$OutDir\portmaster-kext.sys.version"
    if (!(Test-Path $versionFile)) {
        Write-Host "Initial download" -ForegroundColor Green
        Invoke-DownloadDriver $latestVersion
    } else {
        $currentVersion = [version](Get-Content $versionFile)
        if ([version]($latestVersion -replace '-', '.') -gt $currentVersion) {
            Write-Host "New version found: $latestVersion" -ForegroundColor Green
            Invoke-DownloadDriver $latestVersion
        } else {
            Write-Host "No new version found"
        }
    }
} catch {
    Write-Error "Failed to update driver: $_"
    exit 1
}
