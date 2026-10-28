#Requires -Version 5.1
<#
.SYNOPSIS
    Export public metadata from Windows certificate stores as JSON.

.DESCRIPTION
    Opens the selected stores read-only and writes subject, issuer, dates,
    SAN, key size, signature algorithm, and the SHA-256 thumbprint.
    Private keys are not exported. A boolean has_private_key is included so
    you can see which entries have a key, without the key itself.

.PARAMETER StoreLocation
    Certificate store locations. Default: LocalMachine and CurrentUser.

.PARAMETER StoreName
    Store names. Default: My, CA, Root, WebHosting.

.PARAMETER OutFile
    Destination JSON file. Omit it to write JSON to stdout.

.PARAMETER ComputerName
    Host name recorded in the document. This script does not connect remotely.
#>
[CmdletBinding()]
param(
    [ValidateSet("CurrentUser", "LocalMachine")]
    [string[]]$StoreLocation = @("LocalMachine", "CurrentUser"),
    [string[]]$StoreName = @("My", "CA", "Root", "WebHosting"),
    [string]$OutFile,
    [string]$ComputerName
)

Set-StrictMode -Version Latest

function ConvertTo-CertClockSerial {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    # .NET returns the serial in little-endian byte order. Reverse it so it
    # matches the integer serial other CertClock collectors record.
    $bytes = $Certificate.GetSerialNumber()
    if ($null -eq $bytes -or $bytes.Length -eq 0) {
        return ""
    }
    [array]::Reverse($bytes)
    $hex = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
    $trimmed = $hex.TrimStart("0")
    if ([string]::IsNullOrEmpty($trimmed)) {
        return "0"
    }
    return $trimmed
}

function ConvertTo-CertClockThumbprint {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($Certificate.RawData)
    } finally {
        $sha.Dispose()
    }
    return ($hash | ForEach-Object { $_.ToString("x2") }) -join ""
}

function Get-CertClockSan {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($ext in $Certificate.Extensions) {
        if ($ext.Oid.Value -ne "2.5.29.17") {
            continue
        }
        $text = $ext.Format($false)
        foreach ($part in ($text -split ",")) {
            $trimmed = $part.Trim()
            # Windows PowerShell prints "DNS Name=host". .NET on other platforms prints "DNS:host".
            if ($trimmed -match "^(?:DNS Name|DNS|IP Address|IP|RFC822 Name|URI)[:=](.+)$") {
                $names.Add($Matches[1].Trim())
            }
        }
    }
    return @($names)
}

function Get-CertClockIsCa {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    foreach ($ext in $Certificate.Extensions) {
        if ($ext.Oid.Value -ne "2.5.29.19") {
            continue
        }
        $text = $ext.Format($false)
        if ($text -match "Subject Type=CA" -or $text -match "CA:TRUE") {
            return $true
        }
        if ($text -match "Subject Type=End Entity" -or $text -match "CA:FALSE") {
            return $false
        }
    }
    return $null
}

function ConvertTo-CertClockCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$StoreLocationName,
        [Parameter(Mandatory = $true)][string]$StoreNameValue
    )
    $keyType = "unknown"
    $keySize = $null
    try {
        $oid = $Certificate.PublicKey.Oid
        if ($null -ne $oid -and $oid.FriendlyName) {
            $keyType = [string]$oid.FriendlyName
        } elseif ($null -ne $oid -and $oid.Value) {
            $keyType = [string]$oid.Value
        }
    } catch {
        $keyType = "unknown"
    }
    try {
        $keySize = [int]$Certificate.PublicKey.Key.KeySize
    } catch {
        $keySize = $null
    }
    $signature = ""
    try {
        if ($Certificate.SignatureAlgorithm.FriendlyName) {
            $signature = [string]$Certificate.SignatureAlgorithm.FriendlyName
        } else {
            $signature = [string]$Certificate.SignatureAlgorithm.Value
        }
    } catch {
        $signature = ""
    }
    $hasKey = $false
    try {
        $hasKey = [bool]$Certificate.HasPrivateKey
    } catch {
        $hasKey = $false
    }
    return [pscustomobject]@{
        store_location      = $StoreLocationName
        store_name          = $StoreNameValue
        thumbprint_sha256   = ConvertTo-CertClockThumbprint -Certificate $Certificate
        subject             = [string]$Certificate.Subject
        issuer              = [string]$Certificate.Issuer
        serial              = ConvertTo-CertClockSerial -Certificate $Certificate
        not_before          = $Certificate.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        not_after           = $Certificate.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        sans                = @(Get-CertClockSan -Certificate $Certificate)
        key_type            = $keyType
        key_size            = $keySize
        signature_algorithm = $signature
        has_private_key     = $hasKey
        is_ca               = Get-CertClockIsCa -Certificate $Certificate
    }
}

function Get-CertClockStoreCertificate {
    param(
        [Parameter(Mandatory = $true)][string]$StoreLocationName,
        [Parameter(Mandatory = $true)][string]$StoreNameValue
    )
    $flags = [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly
    $flags = $flags -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreNameValue, $StoreLocationName)
    try {
        $store.Open($flags)
    } catch {
        Write-Warning "Could not open ${StoreLocationName}\${StoreNameValue} : $($_.Exception.Message)"
        return @()
    }
    try {
        $items = @()
        foreach ($cert in $store.Certificates) {
            $items += ConvertTo-CertClockCertificate -Certificate $cert -StoreLocationName $StoreLocationName -StoreNameValue $StoreNameValue
        }
        return $items
    } finally {
        $store.Close()
    }
}

function Write-CertClockJson {
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

function Export-CertClockStore {
    param(
        [string[]]$StoreLocation = @("LocalMachine", "CurrentUser"),
        [string[]]$StoreName = @("My", "CA", "Root", "WebHosting"),
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
    $all = @()
    foreach ($location in $StoreLocation) {
        foreach ($name in $StoreName) {
            $all += @(Get-CertClockStoreCertificate -StoreLocationName $location -StoreNameValue $name)
        }
    }
    $document = [pscustomobject]@{
        collector    = "certclock-windows-store"
        version      = 1
        host         = $ComputerName
        collected_at = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        certificates = @($all)
    }
    $json = $document | ConvertTo-Json -Depth 6
    if ($OutFile) {
        Write-CertClockJson -Path $OutFile -Json $json
    } else {
        Write-Output $json
    }
}

if ($MyInvocation.InvocationName -ne ".") {
    Export-CertClockStore -StoreLocation $StoreLocation -StoreName $StoreName -OutFile $OutFile -ComputerName $ComputerName
}
