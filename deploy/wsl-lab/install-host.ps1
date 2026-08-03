[CmdletBinding()]
param(
    [string]$DistroName = "MineShark-Lab",
    [string]$DistroLocation = "E:\WSL\MineShark-Lab",
    [string]$SpoolDirectory = "E:\MineShark-runtime\spool",
    [string]$CaptureInterface = "",
    [switch]$SkipWiresharkInstall,
    [switch]$SkipGuestInstall,
    [switch]$SkipScheduledTasks
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$RuntimeRoot = Split-Path -Parent $SpoolDirectory
$DumpcapCandidates = @(
    "C:\Program Files\Wireshark\dumpcap.exe",
    "C:\Program Files (x86)\Wireshark\dumpcap.exe"
)
$WiresharkUninstallKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter()] [string[]]$ArgumentList = @()
    )

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE"
    }
}

function Get-DumpcapPath {
    foreach ($candidate in $DumpcapCandidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    $registryLocations = Get-ItemProperty -Path $WiresharkUninstallKeys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "Wireshark*" -and $_.InstallLocation } |
        Select-Object -ExpandProperty InstallLocation
    foreach ($location in ($registryLocations | Select-Object -Unique)) {
        $candidate = Join-Path $location "dumpcap.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    return $null
}

function Resolve-CaptureInterface {
    param(
        [Parameter(Mandatory)] [string]$DumpcapPath,
        [Parameter()] [string]$RequestedInterface
    )

    if ($RequestedInterface) {
        return $RequestedInterface
    }
    $interfaces = & $DumpcapPath -D
    if ($LASTEXITCODE -ne 0) {
        throw "dumpcap could not enumerate capture interfaces"
    }
    $wireless = $interfaces | Where-Object { $_ -match "(?i)(Wi-Fi|WLAN|Wireless|802\.11)" } | Select-Object -First 1
    if (-not $wireless) {
        throw "No WLAN capture interface was found. Re-run with -CaptureInterface after checking dumpcap -D."
    }
    $match = [regex]::Match($wireless, "^\s*(\d+)\.")
    if (-not $match.Success) {
        throw "Could not parse dumpcap interface index from: $wireless"
    }
    return $match.Groups[1].Value
}

function Assert-FreshTarget {
    $existingDistros = (& wsl.exe --list --quiet) -replace "`0", ""
    if ($existingDistros | Where-Object { $_.Trim() -eq $DistroName }) {
        throw "WSL distribution already exists: $DistroName"
    }
    if (Test-Path -LiteralPath $DistroLocation) {
        throw "WSL target path already exists: $DistroLocation"
    }
    if (Test-Path -LiteralPath $RuntimeRoot) {
        $existingRuntimeItems = Get-ChildItem -LiteralPath $RuntimeRoot -Force
        if ($existingRuntimeItems) {
            throw "Runtime target is not empty: $RuntimeRoot"
        }
    }
}

function Register-LabTasks {
    param(
        [Parameter(Mandatory)] [string]$DumpcapPath,
        [Parameter(Mandatory)] [string]$Interface
    )

    $captureTaskName = "MineShark-WLANCapture"
    $startupTaskName = "MineShark-Lab-Start"
    foreach ($taskName in ($captureTaskName, $startupTaskName)) {
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            throw "Scheduled task already exists: $taskName"
        }
    }

    $CaptureArguments = @(
        "-i", $Interface,
        "-f", "tcp",
        "-s", "128",
        "-b", "duration:5",
        "-b", "files:60",
        "-w", (Join-Path $SpoolDirectory "mineshark.pcapng")
    )
    $quotedCaptureArguments = $CaptureArguments | ForEach-Object {
        if ($_ -match "\s") { '"' + $_.Replace('"', '\"') + '"' } else { $_ }
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
    $settings = New-ScheduledTaskSettingsSet -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)

    $captureAction = New-ScheduledTaskAction -Execute $DumpcapPath -Argument ($quotedCaptureArguments -join " ")
    Register-ScheduledTask -TaskName $captureTaskName -Action $captureAction -Trigger $trigger -Settings $settings -Principal $principal | Out-Null

    $startupAction = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\wsl.exe" -Argument "-d $DistroName --exec /bin/sleep infinity"
    Register-ScheduledTask -TaskName $startupTaskName -Action $startupAction -Trigger $trigger -Settings $settings -Principal $principal | Out-Null

    Start-ScheduledTask -TaskName $startupTaskName
    Start-ScheduledTask -TaskName $captureTaskName
}

Assert-FreshTarget

$dumpcapPath = Get-DumpcapPath
if (-not $dumpcapPath -and -not $SkipWiresharkInstall) {
    Invoke-NativeCommand -FilePath "winget.exe" -ArgumentList @(
        "install", "--id", "WiresharkFoundation.Wireshark", "--exact", "--silent",
        "--accept-package-agreements", "--accept-source-agreements"
    )
    $dumpcapPath = Get-DumpcapPath
}
if (-not $dumpcapPath) {
    throw "dumpcap.exe was not found. Install Wireshark or remove -SkipWiresharkInstall."
}

New-Item -ItemType Directory -Path (Split-Path -Parent $DistroLocation) -Force | Out-Null
New-Item -ItemType Directory -Path $SpoolDirectory -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $RuntimeRoot "certs") -Force | Out-Null

Invoke-NativeCommand -FilePath "wsl.exe" -ArgumentList @(
    "--install", "Ubuntu-22.04", "--name", $DistroName, "--location", $DistroLocation, "--no-launch"
)

$wslConfiguration = "[boot]`nsystemd=true`n"
$encodedConfiguration = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($wslConfiguration))
Invoke-NativeCommand -FilePath "wsl.exe" -ArgumentList @(
    "-d", $DistroName, "-u", "root", "--", "bash", "-lc",
    "printf '%s' '$encodedConfiguration' | base64 -d > /etc/wsl.conf"
)
Invoke-NativeCommand -FilePath "wsl.exe" -ArgumentList @("--terminate", $DistroName)
Invoke-NativeCommand -FilePath "wsl.exe" -ArgumentList @("-d", $DistroName, "-u", "root", "--", "/bin/true")

if (-not $SkipGuestInstall) {
    $guestInstaller = "/mnt/e/MineShark-product/deploy/wsl-lab/install-guest.sh"
    Invoke-NativeCommand -FilePath "wsl.exe" -ArgumentList @(
        "-d", $DistroName, "-u", "root", "--", "bash", $guestInstaller
    )
}

$captureInterfaceValue = Resolve-CaptureInterface -DumpcapPath $dumpcapPath -RequestedInterface $CaptureInterface
if (-not $SkipScheduledTasks) {
    Register-LabTasks -DumpcapPath $dumpcapPath -Interface $captureInterfaceValue
}

$localCertificate = Join-Path $RuntimeRoot "certs\mineshark-local.crt"
if (Test-Path -LiteralPath $localCertificate -PathType Leaf) {
    Import-Certificate -FilePath $localCertificate -CertStoreLocation "Cert:\CurrentUser\Root" | Out-Null
}

Write-Host "MineShark-Lab host provisioning completed."
Write-Host "Capture interface: $captureInterfaceValue"
Write-Host "Console URL: https://localhost:8012"
