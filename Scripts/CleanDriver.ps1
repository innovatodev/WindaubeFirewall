$driverName = "PortmasterKext"
$maxAttempts = 3
$timeout = 1 # seconds

function Wait-Operation {
    param($operation)
    Start-Sleep -Seconds $timeout
}

try {
    $service = Get-Service -Name $driverName -ErrorAction SilentlyContinue

    if ($service) {
        # Stop service with retries
        for ($i = 1; $i -le $maxAttempts; $i++) {
            Write-Host "Stopping $driverName service (attempt $i of $maxAttempts)..."
            try {
                Stop-Service -Name $driverName -Force -ErrorAction Stop
                Wait-Operation "stop"
                break
            } catch {
                if ($i -eq $maxAttempts) { throw $_ }
                Write-Host "Retry stopping service..."
            }
        }

        # Delete service with retries
        for ($i = 1; $i -le $maxAttempts; $i++) {
            Write-Host "Removing $driverName service (attempt $i of $maxAttempts)..."
            try {
                sc.exe delete $driverName
                Wait-Operation "delete"
                break
            } catch {
                if ($i -eq $maxAttempts) { throw $_ }
                Write-Host "Retry removing service..."
            }
        }
    } else {
        Write-Host "$driverName service not found"
    }
} catch {
    Write-Error "Error occurred: $_"
    exit 1
}

Write-Host "Driver cleanup completed"
