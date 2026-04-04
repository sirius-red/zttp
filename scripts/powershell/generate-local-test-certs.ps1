[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutDir = ".tmp/local-certs"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$encoding = [System.Text.UTF8Encoding]::new($false)
$resolvedOutDir = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $OutDir))

[System.IO.Directory]::CreateDirectory($resolvedOutDir) | Out-Null

$certificatePath = Join-Path $resolvedOutDir "loopback-server.pem"
$privateKeyPath = Join-Path $resolvedOutDir "loopback-server.key"
$rootsPath = Join-Path $resolvedOutDir "roots.pem"

$subject = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new("CN=localhost")
$key = [System.Security.Cryptography.ECDsa]::Create(
    [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName("nistP256")
)

try {
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $subject,
        $key,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )

    $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $san.AddDnsName("localhost")
    $san.AddDnsName("loopback.local")
    $san.AddIpAddress([System.Net.IPAddress]::Parse("127.0.0.1"))
    $san.AddIpAddress([System.Net.IPAddress]::Parse("::1"))

    $request.CertificateExtensions.Add($san.Build())
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $false)
    )
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
            $true
        )
    )

    $eku = [System.Security.Cryptography.OidCollection]::new()
    [void]$eku.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.1", "Server Authentication"))
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku, $false)
    )
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($request.PublicKey, $false)
    )

    $notBefore = [System.DateTimeOffset]::UtcNow.AddMinutes(-5)
    $notAfter = $notBefore.AddDays(825)
    $certificate = $request.CreateSelfSigned($notBefore, $notAfter)

    try {
        $certificatePem = $certificate.ExportCertificatePem()
        $privateKeyPem = $key.ExportPkcs8PrivateKeyPem()

        [System.IO.File]::WriteAllText($certificatePath, $certificatePem, $encoding)
        [System.IO.File]::WriteAllText($privateKeyPath, $privateKeyPem, $encoding)
        [System.IO.File]::WriteAllText($rootsPath, $certificatePem, $encoding)
    }
    finally {
        $certificate.Dispose()
    }
}
finally {
    $key.Dispose()
}

Write-Output "Generated local TLS credentials:"
Write-Output "  Certificate: $certificatePath"
Write-Output "  Private key: $privateKeyPath"
Write-Output "  Trust roots: $rootsPath"
