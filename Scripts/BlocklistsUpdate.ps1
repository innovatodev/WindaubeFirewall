$ErrorActionPreference = "Stop"

function Add-UniqueItem {
    param (
        [System.Collections.ArrayList]$List,
        [string]$Item,
        [switch]$IsDomain
    )

    $Item = $Item.Trim()
    if ($IsDomain) { $Item = $Item.TrimStart("www.") }
    $null = $List.Add($Item)
}

function Invoke-ProcessBlocklists {
    param (
        [string[]]$Content,
        [System.Collections.ArrayList]$Domains,
        [System.Collections.ArrayList]$IPs
    )

    foreach ($line in $Content) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("#")) { continue }

        switch -Regex ($line) {
            # IP with domain comment
            "([0-9a-fA-F:\.]+)\s+#\s+(.+)" {
                Add-UniqueItem -List $IPs -Item $matches[1]
                Add-UniqueItem -List $Domains -Item $matches[2] -IsDomain
            }
            # IPv4
            "^\d+\.\d+\.\d+\.\d+$" {
                Add-UniqueItem -List $IPs -Item $line
            }
            # IPv6
            "^[0-9a-fA-F:]+::[0-9a-fA-F:]*$" {
                Add-UniqueItem -List $IPs -Item $line
            }
            # Domain
            default {
                Add-UniqueItem -List $Domains -Item $line -IsDomain
            }
        }
    }
}

try {
    $BlockLists = @(
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-onlydomains.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/doh.txt",
        "https://raw.githubusercontent.com/jameshas/Public-DoH-Lists/refs/heads/main/lists/doh_ips_plain.txt",
        "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv4.txt",
        "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv6.txt"
    )

    $OutDir = "$PSScriptRoot\..\Data\Blocklists\BuiltIn"
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

    $DOMAINS = [System.Collections.ArrayList]::new()
    $IPS = [System.Collections.ArrayList]::new()

    $total = $BlockLists.Count
    $current = 0

    foreach ($url in $BlockLists) {
        $current++
        Write-Progress -Activity "Downloading Blocklists" -Status "List $current of $total" -PercentComplete (($current / $total) * 100)

        $content = (Invoke-WebRequest -Uri $url).Content.Split([Environment]::NewLine)
        Invoke-ProcessBlocklists -Content $content -Domains $DOMAINS -IPs $IPS
    }

    Write-Progress -Activity "Downloading Blocklists" -Completed

    # Process and save results
    $DOMAINS = $DOMAINS | Select-Object -Unique | Sort-Object
    $IPS = $IPS | Select-Object -Unique | Sort-Object

    $DOMAINS | Set-Content -Path (Join-Path $OutDir "DNS_DOMAINS.txt")
    $IPS | Set-Content -Path (Join-Path $OutDir "DNS_IP.txt")

    Write-Host "Successfully updated blocklists:"
    Write-Host "Domains: $($DOMAINS.Count)"
    Write-Host "IPs: $($IPS.Count)"
} catch {
    Write-Error "Failed to update blocklists: $_"
    exit 1
}
