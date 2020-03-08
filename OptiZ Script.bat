@echo off
title OptiZ_Script
Echo.
Echo.
Echo.

Echo. [101;41mDisable Windows Cortana / Search?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mmY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /v "AllowCortana" /t REG_DWORD /d "0" /f
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f
sc config wsearch start= disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
sc config PimIndexMaintenanceSvc_29d41 start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Microsoft Sign-in / Log-in?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mmY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config NgcSvc start= disabled
sc config NgcCtnrSvc start= disabled
sc config wlidsvc start= disabled
Echo. [101;41mThe services has been disabled.[0m

goto next

:next
Echo. [101;41mDisable Microsoft Xbox?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mmY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config XboxNetApiSvc start= disabled
sc config XblGameSave start= disabled
sc config XblAuthManager start= disabled
sc config xbgm start= disabled
sc config XboxGipSvc start= disabled
sc config BcastDVRUserService_2e090 start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next


:next
Echo. [101;41mDisable Wi-Fi? (Please Skip If You Are Using Wi-Fi!):[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mmY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config WwanSvc start= disabled
sc config WlanSvc start= disabled
sc config wcncsvc start= disabled
sc config lmhosts start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Router Support?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config WwanSvc start= disabled
sc config WlanSvc start= disabled
sc config SmsRouter start= disabled
sc config AJRouter start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable BitLocker?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config BDESVC start= disabled
sc config 
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Telemetry and Diagnostics?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config DiagTrack start= disabled
sc config diagsvc start= disabled
sc config DPS start= disabled
sc config WdiServiceHost start= disabled
sc config WdiSystemHost start= disabled
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
sc config dmwappushsvc start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config TroubleshootingSvc start= disabled
sc config UserDataSvc_29d41 start= disabled
sc config UnistoreSvc_29d41 start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Bluetooth Support?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config BTAGService start= disabled
sc config bthserv start= disabled
sc config BthAvctpSvc start= disabled
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d 00000004 /f
sc config DevicesFlowUserSvc_2e090 start= disabled
sc config ConsentUxUserSvc_29d41 start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Windows Restore and Backup (Not Recommended)?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config wbengine start= disabled
sc config fhsvc start= disabled
sc config swprv start= disabled
sc config VSS start= disabled
sc config SDRSVC start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Windows Update?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config wuauserv start= disabled
sc config WaaSMedicSvc start= disabled
sc config PeerDistSvc start= disabled
sc config UsoSvc start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Windows Defender?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config Sense start= disabled
sc config WdNisSvc start= disabled
sc config WinDefend start= disabled
sc config SamSs start= disabled
sc config wscsvc start= disabled
sc config SgrmBroker start= disabled
sc config SecurityHealthService start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Windows Firewall?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config mpssvc start= disabled
sc config BFE start= disabled
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DisableNotifications" /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DoNotAllowExceptions" /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DoNotAllowExceptions" /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DisableNotifications" /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DoNotAllowExceptions" /t REG_DWORD /d 00000001 /f
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Hyper-V?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config HvHost start= disabled
sc config vmickvpexchange start= disabled
sc config vmicguestinterface start= disabled
sc config vmicshutdown start= disabled
sc config vmicheartbeat start= disabled
sc config vmicvmsession start= disabled
sc config vmicrdv start= disabled
sc config vmictimesync start= disabled
sc config vmicvss start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Windows Error Reporting and Windows Push Notifications?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config WerSvc start= disabled
sc config WpnService start= disabled
sc config WpnUserService_29f91 start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Remote Desktop?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config RasAuto start= disabled
sc config RasMan start= disabled
sc config SessionEnv start= disabled
sc config TermService start= disabled
sc config UmRdpService start= disabled
sc config RemoteRegistry start= disabled
sc config RpcLocator start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Remote Desktop?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config RasAuto start= disabled
sc config RasMan start= disabled
sc config SessionEnv start= disabled
sc config TermService start= disabled
sc config UmRdpService start= disabled
sc config RemoteRegistry start= disabled
sc config RpcLocator start= disabled
sc config RemoteAccess start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Print?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config LanmanServer start= disabled
sc config Fax start= disabled
sc config Spooler start= disabled
sc config PrintNotify start= disabled
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc_2c95b" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" /v "Start" /t REG_DWORD /d "4" /f

Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Smart Card?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config SCardSvr start= disabled
sc config ScDeviceEnum start= disabled
sc config SCPolicySvc start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Tablet support?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config TabletInputService start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Task Scheduler?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config Schedule start= disabled
sc config TimeBrokerSvc start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mWould you like to tweak unneeded services?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config TapiSrv start= disabled
sc config WpcMonSvc start= disabled
sc config SEMgrSvc start= disabled
sc config PNRPsvc start= disabled
sc config p2psvc start= disabled
sc config p2pimsvc start= disabled
sc config PhoneSvc start= disabled
sc config PlugPlay start= disabled
sc config RmSvc start= disabled
sc config SensorDataService start= disabled
sc config SensrSvc start= disabled
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WalletService" /v "Start" /t REG_DWORD /d "4" /f
sc config SensorService start= disabled
sc config shpamsvc start= disabled
sc config svsvc start= disabled
sc config OneSyncSvc_29d41 start= disabled
sc config SysMain start= disabled
sc config MSiSCSI start= disabled
sc config Netlogon start= disabled
sc config CscService start= disabled
sc config ssh-agent start= disabled
sc config AppReadiness start= disabled
sc config AppXSVC start= disabled
sc config tzautoupdate start= disabled
sc config CaptureService_29d41
sc config NfsClnt start= disabled
sc config WbioSrvc start= disabled
sc config wisvc start= disabled
sc config defragsvc start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

Echo.
Echo.
Echo.
Echo. [101;43Please Restart Your Computer After The Script Done![0m
