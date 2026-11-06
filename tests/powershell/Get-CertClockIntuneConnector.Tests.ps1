#Requires -Version 5.1
BeforeAll {
    $script = Join-Path $PSScriptRoot "..\..\src\certclock\bundled\Get-CertClockIntuneConnector.ps1"
    . $script
    if (-not (Get-Command Get-WinEvent -ErrorAction SilentlyContinue)) {
        # Get-WinEvent only exists on Windows. A stub lets Mock work elsewhere.
        function global:Get-WinEvent { param($FilterHashtable, $ErrorAction) }
    }
}

Describe "ConvertTo-CertClockIntuneEvent" {
    It "keeps id, UTC time, level and log name, and drops the message" {
        $record = [pscustomobject]@{
            Id               = 5002
            TimeCreated      = [DateTime]::SpecifyKind([DateTime]"2026-11-02T08:15:00", [DateTimeKind]::Utc)
            LevelDisplayName = "Error"
            LogName          = "unit-test/Operational"
            Message          = "device 00000000-0000-0000-0000-000000000000 user unit@example.test"
        }
        $converted = ConvertTo-CertClockIntuneEvent -EventRecord $record
        $converted.id | Should -Be 5002
        $converted.time_created | Should -Be "2026-11-02T08:15:00Z"
        $converted.level | Should -Be "Error"
        @($converted.PSObject.Properties.Name) | Should -Not -Contain "message"
        ($converted | ConvertTo-Json) | Should -Not -Match "example.test"
    }
}

Describe "ConvertTo-CertClockIntuneDocument" {
    It "writes the collector header the Python side expects" {
        $doc = ConvertTo-CertClockIntuneDocument -ComputerName "UNIT-01" -Hours 24
        $doc.collector | Should -Be "certclock-intune-connector"
        $doc.version | Should -Be 1
        $doc.provider | Should -Be "Microsoft-Intune-CertificateConnectors"
        @($doc.events).Count | Should -Be 0
    }
}

Describe "Export-CertClockIntuneConnector" {
    It "writes a document even when the event source is missing" {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("certclock-" + [guid]::NewGuid().ToString("n"))
        New-Item -ItemType Directory -Path $dir | Out-Null
        $out = Join-Path $dir "intune.json"
        Mock Get-WinEvent { throw [System.Exception]::new("unit: no such provider") }
        Export-CertClockIntuneConnector -Hours 1 -OutFile $out -ComputerName "UNIT-01"
        $doc = Get-Content -Raw -LiteralPath $out | ConvertFrom-Json
        $doc.host | Should -Be "UNIT-01"
        @($doc.errors).Count | Should -Be 1
        Remove-Item -LiteralPath $dir -Recurse -Force
    }
}
