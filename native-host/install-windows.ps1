param(
  [switch]$Chrome,
  [switch]$Chromium,
  [switch]$Edge,
  [switch]$Brave,
  [switch]$Firefox,
  [string]$ExtensionId,
  [string]$ChromeExtensionId,
  [string]$ChromiumExtensionId,
  [string]$EdgeExtensionId,
  [string]$BraveExtensionId,
  [string]$HostPath
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$defaultHostPath = Join-Path $scriptDir "com.pubkey.auth.py"

if (-not $HostPath) {
  $HostPath = $defaultHostPath
}

if (-not (Test-Path -LiteralPath $HostPath)) {
  throw "Host script not found: $HostPath"
}

$installChrome = $Chrome.IsPresent
$installChromium = $Chromium.IsPresent
$installEdge = $Edge.IsPresent
$installBrave = $Brave.IsPresent
$installFirefox = $Firefox.IsPresent

if (-not $installChrome -and -not $installChromium -and -not $installEdge -and -not $installBrave -and -not $installFirefox) {
  $installChrome = $true
  $installChromium = $true
  $installEdge = $true
  $installBrave = $true
  $installFirefox = $true
}

$anyChromium = $installChrome -or $installChromium -or $installEdge -or $installBrave
if ($anyChromium -and -not $ExtensionId -and -not $ChromeExtensionId -and -not $ChromiumExtensionId -and -not $EdgeExtensionId -and -not $BraveExtensionId) {
  throw "Extension ID is required for Chromium-based browsers. Use -ExtensionId or browser-specific IDs."
}

function Resolve-ExtensionId([string]$browser) {
  switch ($browser) {
    "chrome" { if ($ChromeExtensionId) { return $ChromeExtensionId }; return $ExtensionId }
    "chromium" { if ($ChromiumExtensionId) { return $ChromiumExtensionId }; return $ExtensionId }
    "edge" { if ($EdgeExtensionId) { return $EdgeExtensionId }; return $ExtensionId }
    "brave" { if ($BraveExtensionId) { return $BraveExtensionId }; return $ExtensionId }
    default { return "" }
  }
}

function Write-HostManifest([string]$browser, [string]$destPath, [string]$registryPath, [string]$extId) {
  $manifestDir = Split-Path -Parent $destPath
  New-Item -ItemType Directory -Path $manifestDir -Force | Out-Null

  $manifest = @{
    name = "com.pubkey.auth"
    description = "Pubkey auth native messaging host"
    path = $HostPath
    type = "stdio"
  }

  if ($browser -eq "firefox") {
    $manifest.allowed_extensions = @("sshkey-web-auth@example.local")
  } else {
    if (-not $extId) {
      throw "Missing extension ID for $browser"
    }
    $manifest.allowed_origins = @("chrome-extension://$extId/")
  }

  ($manifest | ConvertTo-Json -Depth 6) | Set-Content -Path $destPath -Encoding UTF8
  New-Item -Path $registryPath -Force | Out-Null
  New-ItemProperty -Path $registryPath -Name "(default)" -PropertyType String -Value $destPath -Force | Out-Null
  Write-Output "Installed: $destPath"
  Write-Output "Registered: $registryPath"
}

$base = Join-Path $env:LOCALAPPDATA "PubkeyAuth\NativeMessagingHosts"

if ($installChrome) {
  $dest = Join-Path $base "chrome\com.pubkey.auth.json"
  Write-HostManifest "chrome" $dest "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.pubkey.auth" (Resolve-ExtensionId "chrome")
}

if ($installChromium) {
  $dest = Join-Path $base "chromium\com.pubkey.auth.json"
  Write-HostManifest "chromium" $dest "HKCU:\Software\Chromium\NativeMessagingHosts\com.pubkey.auth" (Resolve-ExtensionId "chromium")
}

if ($installEdge) {
  $dest = Join-Path $base "edge\com.pubkey.auth.json"
  Write-HostManifest "edge" $dest "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.pubkey.auth" (Resolve-ExtensionId "edge")
}

if ($installBrave) {
  $dest = Join-Path $base "brave\com.pubkey.auth.json"
  Write-HostManifest "brave" $dest "HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.pubkey.auth" (Resolve-ExtensionId "brave")
}

if ($installFirefox) {
  $dest = Join-Path $base "firefox\com.pubkey.auth.json"
  Write-HostManifest "firefox" $dest "HKCU:\Software\Mozilla\NativeMessagingHosts\com.pubkey.auth" ""
}

Write-Output "Done."
Write-Output "Optional key override: `$env:PUBKEY_AUTH_KEY_PATH = '~/.ssh/id_ed25519'"
