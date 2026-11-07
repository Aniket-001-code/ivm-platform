$ErrorActionPreference = 'Stop'
$certDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'tls-certs'
New-Item -ItemType Directory -Force -Path $certDir | Out-Null
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout (Join-Path $certDir 'localhost.key') -out (Join-Path $certDir 'localhost.crt') -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
Write-Host "Created local self-signed certificate files in $certDir"
