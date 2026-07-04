# Purple Loop — Windows victim provisioning
# Run as Administrator in PowerShell
# Manager IP: 192.168.88.3

$ErrorActionPreference = "Stop"
$manager = "192.168.88.3"
$agent = "windows-vm"

Write-Host "=== Installing Wazuh Agent 4.9.2 ==="
$msi = "$env:TEMP\wazuh-agent.msi"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi" -OutFile $msi
Start-Process msiexec.exe -ArgumentList "/i $msi /qn WAZUH_MANAGER=$manager WAZUH_AGENT_NAME=$agent WAZUH_REGISTRATION_SERVER=$manager" -Wait
NET START Wazuh
Write-Host "Wazuh agent installed and started."

Write-Host "=== Installing Sysmon ==="
$sysmon = "$env:TEMP\Sysmon64.exe"
$config = "$env:TEMP\sysmon-config.xml"
Invoke-WebRequest -Uri "https://live.sysinternals.com/Sysmon64.exe" -OutFile $sysmon
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile $config
& $sysmon -accepteula -i $config
Write-Host "Sysmon installed."

Write-Host "=== Done. Agent: $agent → Manager: $manager ==="
Get-Service Wazuh, Sysmon64 | Format-Table Name, Status
