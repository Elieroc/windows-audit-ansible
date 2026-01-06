#!/bin/bash

# Test du script PowerShell exact utilisé dans l'audit
echo "=== Test du script complet ==="
ansible windows -i ~/windows-audit-ansible-main/inventory.ini -m win_shell -a '
$ErrorActionPreference = "SilentlyContinue"
try {
  $allApps = @()
  
  # Récupérer depuis 64-bit
  $apps64 = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
    Where-Object { $_.DisplayName -ne $null -and $_.DisplayName -ne "" }
  
  foreach ($app in $apps64) {
    $allApps += [PSCustomObject]@{
      DisplayName = $app.DisplayName
      DisplayVersion = if ($app.DisplayVersion) { $app.DisplayVersion } else { "Unknown" }
      Publisher = if ($app.Publisher) { $app.Publisher } else { "N/A" }
      InstallDate = if ($app.InstallDate) { $app.InstallDate } else { "N/A" }
      Architecture = "64-bit"
    }
  }
  
  Write-Output "DEBUG: apps64 count = $($apps64.Count)"
  Write-Output "DEBUG: allApps count = $($allApps.Count)"
  
  if ($allApps.Count -gt 0) {
    Write-Output "InstalledApplications:Count=$($allApps.Count)"
    Write-Output "==========================================="
    foreach ($app in $allApps) {
      Write-Output "$($app.DisplayName) | v$($app.DisplayVersion) | Publisher: $($app.Publisher) | Installed: $($app.InstallDate) | Arch: $($app.Architecture)"
    }
    Write-Output "==========================================="
  } else {
    Write-Output "NoApplicationsDetected"
  }
} catch {
  Write-Output "Error: $($_.Exception.Message)"
}
'

echo ""
echo "=== Connexion interactive avec evil-winrm ==="
evil-winrm -i 192.168.8.63 -u 'Administrator' -p 'sup3rAdm1nP@sswd!!'
