#Requires -Version 5.1
<#
.SYNOPSIS
    Export Certificate Connector for Microsoft Intune events as JSON.

.DESCRIPTION
    Runs on the server that hosts the Certificate Connector for Microsoft
    Intune. Reads events from the documented event source
    Microsoft-Intune-CertificateConnectors (Event Viewer > Applications and
    Services Logs > Microsoft > Intune > CertificateConnectors > Admin and
    Operational) and writes event ID, time (UTC), level and log name.

    The script only reads. It does not export message text, because the
    events can contain device IDs, user IDs and certificate thumbprints.

    Evaluate the export with: certclock intune-connector --path <file>

    Sources (Microsoft Learn):
    https://learn.microsoft.com/en-us/intune/fundamentals/certificates/connector/overview#logging
    https://learn.microsoft.com/en-us/intune/fundamentals/certificates/connector/setup-connector

.PARAMETER Hours
    How far back to read. Default: 168 (seven days).

.PARAMETER OutFile
    Destination JSON file. Omit it to write JSON to stdout.

.PARAMETER ComputerName
    Host name recorded in the document. This script does not connect remotely.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 8760)]
    [int]$Hours = 168,
    [string]$OutFile,
    [string]$ComputerName
)

Set-StrictMode -Version Latest

$script:CertClockIntuneProvider = "Microsoft-Intune-CertificateConnectors"

function ConvertTo-CertClockIntuneEvent {
    param(
        [Parameter(Mandatory = $true)]$EventRecord
    )
    $created = [DateTime]$EventRecord.TimeCreated
    [pscustomobject]@{
        id           = [int]$EventRecord.Id
        time_created = $created.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        level        = [string]$EventRecord.LevelDisplayName
        log_name     = [string]$EventRecord.LogName
    }
}

function Get-CertClockIntuneEvent {
    param(
        [Parameter(Mandatory = $true)][int]$Hours
    )
    $errors = @()
    $records = @()
    $filter = @{
        ProviderName = $script:CertClockIntuneProvider
        StartTime    = (Get-Date).AddHours(-$Hours)
    }
    try {
        $records = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -notlike "NoMatchingEventsFound*") {
            $errors += $_.Exception.Message
        }
    }
    [pscustomobject]@{
        events = @($records | ForEach-Object { ConvertTo-CertClockIntuneEvent -EventRecord $_ })
        errors = @($errors)
    }
}

function Write-CertClockIntuneJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Json
    )
    $full = $Path
    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        $full = Join-Path (Get-Location) $Path
    }
    $parent = Split-Path -Parent $full
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        throw "Directory does not exist: $parent"
    }
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($full, $Json, $utf8)
}

function ConvertTo-CertClockIntuneDocument {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][int]$Hours,
        [object[]]$Events = @(),
        [string[]]$Errors = @()
    )
    [pscustomobject]@{
        collector    = "certclock-intune-connector"
        version      = 1
        host         = $ComputerName
        provider     = $script:CertClockIntuneProvider
        hours        = $Hours
        collected_at = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        events       = @($Events)
        errors       = @($Errors)
    }
}

function Export-CertClockIntuneConnector {
    param(
        [int]$Hours = 168,
        [string]$OutFile,
        [string]$ComputerName
    )
    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        if ($env:COMPUTERNAME) {
            $ComputerName = $env:COMPUTERNAME
        } else {
            $ComputerName = "localhost"
        }
    }
    $result = Get-CertClockIntuneEvent -Hours $Hours
    $document = ConvertTo-CertClockIntuneDocument -ComputerName $ComputerName -Hours $Hours -Events $result.events -Errors $result.errors
    $json = $document | ConvertTo-Json -Depth 5
    if ($OutFile) {
        Write-CertClockIntuneJson -Path $OutFile -Json $json
    } else {
        Write-Output $json
    }
}

if ($MyInvocation.InvocationName -ne ".") {
    Export-CertClockIntuneConnector -Hours $Hours -OutFile $OutFile -ComputerName $ComputerName
}
