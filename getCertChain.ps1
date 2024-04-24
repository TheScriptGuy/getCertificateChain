# Author:          TheScriptGuy (and in this case AI too)
# Last modified:   2024-04-24
# Version:         0.01
# Description:     Help download the certificate chain in Windows and output the files to the current directory.

param(
  [string]$hostname,
  [switch]$useAIA
)

function Sanitize-FileName($name) {
  $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $invalidRegStr = "[" + [RegEx]::Escape($invalidChars) + "]"
  return ($name -replace $invalidRegStr -replace '\s', '-' -replace '\*', '')
}

function Get-CertificateFromAIA($cert) {
  $aia = $cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Authority Information Access"}
  if (-not $aia) {
    throw "AIA field not found in certificate"
  }

  # Try to extract the CA Issuers URL from AIA
  $aiaText = $aia.Format($false)
  $aiaUri = [regex]::Match($aiaText, '(http|https)://[^\s,]*(\.crt|\.cer|\.der)').Value

  if (-not $aiaUri) {
    Write-Host "CA Issuers URL not found or only OCSP URL present. Continuing without downloading for certificate: $($cert.Subject)"
    return $null
  }

  try {
    $response = Invoke-WebRequest -Uri $aiaUri -UseBasicParsing
    $certBytes = $response.Content

    # Convert from DER to PEM if necessary
    $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $x509.Import($certBytes)
    $base64Cert = [System.Convert]::ToBase64String($x509.RawData)
    $pemCert = "-----BEGIN CERTIFICATE-----`n$([System.Text.RegularExpressions.Regex]::Split($base64Cert, '(.{64})' -join '`n'))`n-----END CERTIFICATE-----"

    return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $x509
  } catch {
    throw "Failed to download or convert certificate from CA Issuers URL: $aiaUri"
  }
}

function Export-CertificateChain($hostname, $useAIA) {
  [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
  $tcpClient = New-Object System.Net.Sockets.TcpClient
  $tcpClient.Connect($hostname, 443)
  $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, {$true})
  $sslStream.AuthenticateAsClient($hostname)

  $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
  $chain.Build($sslStream.RemoteCertificate)
  $combinedCertificates = ""
  $i = 0

  foreach ($element in $chain.ChainElements) {
    $cert = $element.Certificate
    $name = ''
    $san = $cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Subject Alternative Name"}
    if ($san) {
      $name = $san.Format($false) -replace 'DNS Name=', '' -split ', ' | Select-Object -First 1
    }
    if (-not $name) {
      $name = $cert.Subject -replace '.*CN=([^,]*).*', '$1'
    }

    $fileName = Sanitize-FileName $name
    $fileName = "$i-$fileName.crt"

    $base64Cert = [System.Convert]::ToBase64String($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    $base64Cert | Set-Content $fileName
    $combinedCertificates += "$base64Cert`r`n"

    if ($useAIA.IsPresent -and $i -lt $chain.ChainElements.Count - 1) {
      try {
        $cert = Get-CertificateFromAIA $cert
      } catch {
        Write-Host $_.Exception.Message "at $fileName"
        break
      }
    }

    $i++
  }

  $combinedCertificates | Set-Content "combined-certificates.crt"
  $sslStream.Close()
  $tcpClient.Close()
}

Export-CertificateChain -hostname $hostname -useAIA:$useAIA
