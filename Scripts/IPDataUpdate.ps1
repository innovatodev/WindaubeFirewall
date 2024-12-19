$ErrorActionPreference = "Stop"

$OutDir = "$PSScriptRoot\..\Data\IPData"
$Uri_Prefix = "https://updates.safing.io"

function Compare-Versions {
    param (
        [string]$Version1,
        [string]$Version2
    )

    $v1Parts = $Version1 -split '-'
    $v2Parts = $Version2 -split '-'

    # Compare each part numerically
    for ($i = 0; $i -lt [Math]::Min($v1Parts.Length, $v2Parts.Length); $i++) {
        $num1 = [int64]$v1Parts[$i]
        $num2 = [int64]$v2Parts[$i]
        if ($num1 -ne $num2) {
            return $num1.CompareTo($num2)
        }
    }

    return $v1Parts.Length.CompareTo($v2Parts.Length)
}

function Get-FileVersion {
    param ([string]$FileType)

    $versionFile = "$OutDir\$FileType.mmdb.version"
    if (!(Test-Path $versionFile)) {
        return $null
    }
    return Get-Content $versionFile
}

function Invoke-DownloadIPData {
    param (
        [string]$Version,
        [string]$Source,
        [string]$Dest
    )

    $fullDest = Join-Path $OutDir $Dest
    $versionFile = "$fullDest.version"
    $tempFile = Join-Path $OutDir "$Source.tmp"

    Remove-Item -Path $fullDest -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue

    # Download and decompress
    Invoke-WebRequest -Uri "$Uri_Prefix/all/intel/geoip/$Source" -OutFile $tempFile
    $inputfile = New-Object System.IO.FileStream $tempFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read)
    $output = New-Object System.IO.FileStream $fullDest, ([IO.FileMode]::Create), ([IO.FileAccess]::Write)
    $gzipStream = New-Object System.IO.Compression.GZipStream $inputfile, ([System.IO.Compression.CompressionMode]::Decompress)
    $gzipStream.CopyTo($output)

    # Cleanup
    $gzipStream.Close()
    $output.Close()
    $inputfile.Close()
    Remove-Item -Path $tempFile -Force

    # Set version for this specific file
    Set-Content -Path $versionFile -Value $Version
}

try {
    # Get latest version
    Write-Host "Downloading beta.json"
    $jsonContent = Invoke-WebRequest -Uri "$Uri_Prefix/beta.json" -ErrorAction Stop | ConvertFrom-Json

    $files = @(
        @{source="geoipv4-mini"; dest="geoipv4-mini.mmdb"},
        @{source="geoipv6-mini"; dest="geoipv6-mini.mmdb"},
        @{source="geoipv4"; dest="geoipv4.mmdb"},
        @{source="geoipv6"; dest="geoipv6.mmdb"}
    )

    foreach ($file in $files) {
        $versionKey = "all/intel/geoip/$($file.source).mmdb.gz"
        $latestVersion = $jsonContent.$versionKey
        if (-not $latestVersion) {
            Write-Host "Skipping $($file.source): Version information not found" -ForegroundColor Yellow
            continue
        }

        $latestVersion = $latestVersion -replace '\.', '-'
        $currentVersion = Get-FileVersion $file.source

        Write-Host "`nChecking $($file.source):"
        Write-Host "Current version: $currentVersion"
        Write-Host "Latest version: $latestVersion"

        if (-not $currentVersion -or (Compare-Versions $latestVersion $currentVersion) -gt 0) {
            Write-Host "Downloading new version" -ForegroundColor Green
            Invoke-DownloadIPData $latestVersion "$($file.source)_v$latestVersion.mmdb.gz" $file.dest
        } else {
            Write-Host "No update needed" -ForegroundColor Gray
        }
    }
} catch {
    Write-Error "Failed to update IP data: $($_.Exception.Message)"
    exit 1
}
