#Requires -Version 5.1
BeforeAll {
    $script = Join-Path $PSScriptRoot "..\..\src\certpilot\bundled\Get-CertPilotStore.ps1"
    . $script
}

Describe "ConvertTo-CertPilotCertificate" {
    It "exports public metadata and not the private key" {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $subject = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new("CN=unit.example.test")
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $subject,
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        $san.AddDnsName("unit.example.test")
        $request.CertificateExtensions.Add($san.Build())
        $cert = $request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddDays(-1),
            [DateTimeOffset]::UtcNow.AddDays(30)
        )

        $record = ConvertTo-CertPilotCertificate -Certificate $cert -StoreLocationName "CurrentUser" -StoreNameValue "My"
        $json = $record | ConvertTo-Json -Depth 6

        $sha = [System.Security.Cryptography.SHA256]::Create()
        $expected = ($sha.ComputeHash($cert.RawData) | ForEach-Object { $_.ToString("x2") }) -join ""
        $sha.Dispose()
        $record.thumbprint_sha256 | Should -Be $expected

        $serialBytes = $cert.GetSerialNumber()
        [array]::Reverse($serialBytes)
        $expectedSerial = (($serialBytes | ForEach-Object { $_.ToString("x2") }) -join "").TrimStart("0")
        $record.serial | Should -Be $expectedSerial

        $record.sans | Should -Contain "unit.example.test"
        $record.store_location | Should -Be "CurrentUser"
        $record.has_private_key | Should -BeOfType ([bool])
        $json | Should -Not -Match "BEGIN PRIVATE KEY"
        $json | Should -Not -Match "RSAParameters"
        @($record.PSObject.Properties.Name) | Should -Not -Contain "RawData"
    }
}

Describe "Export-CertPilotStore" {
    It "writes a document when a store cannot be opened" {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("certpilot-" + [guid]::NewGuid().ToString("n"))
        New-Item -ItemType Directory -Path $dir | Out-Null
        $out = Join-Path $dir "stores.json"
        Export-CertPilotStore -StoreLocation @("CurrentUser") -StoreName @("My") -OutFile $out -ComputerName "UNIT-01"
        $doc = Get-Content -Raw -LiteralPath $out | ConvertFrom-Json
        $doc.collector | Should -Be "certpilot-windows-store"
        $doc.host | Should -Be "UNIT-01"
        $doc.version | Should -Be 1
        Remove-Item -LiteralPath $dir -Recurse -Force
    }
}
