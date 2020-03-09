@echo off
title OptiZ_Script
Echo.
Echo.
Echo.

Echo. [101;41mDisable Windows Search?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowCortana" /t REG_DWORD /d 00000000 /f
Reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /v "AllowCortana" /t REG_DWORD /d 00000000 /f
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 00000000 /f
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f
sc config wsearch start= disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 00000000 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 00000000 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 00000000 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 00000001 /f
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Microsoft Sign-in / Log-in?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
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
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config XboxNetApiSvc start= disabled
sc config XblGameSave start= disabled
sc config XblAuthManager start= disabled
sc config xbgm start= disabled
sc config XboxGipSvc start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next


:next
Echo. [101;41mDisable Wi-Fi? (Please Skip If You Are Using Wi-Fi!):[0m
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
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 00000000 /f
sc config dmwappushsvc start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config TroubleshootingSvc start= disabled
sc config DsSvc start= disabled
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
sc config NaturalAuthentication start= disabled
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d 00000004 /f
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
sc config DoSvc start= disabled
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
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WpnUserService" /v "Start" /t REG_DWORD /d 00000004 /f
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
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PrintWorkflowUserSvc" /v "Start" /t REG_DWORD /d 00000004 /f
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
sc config CertPropSvc start= disabled
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
Echo. [101;41mDisable Program Compatibility Assistant?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
sc config PcaSvc start= disabled
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
sc config FontCache3.0.0.0 start= disabled
sc config WpcMonSvc start= disabled
sc config SEMgrSvc start= disabled
sc config PNRPsvc start= disabled
sc config LanmanWorkstation start= disabled
sc config WEPHOSTSVC start= disabled
sc config p2psvc start= disabled
sc config p2pimsvc start= disabled
sc config PhoneSvc start= disabled
sc config PlugPlay start= disabled
sc config Wecsvc start= disabled
sc config RmSvc start= disabled
sc config SensorDataService start= disabled
sc config SensrSvc start= disabled
sc config perceptionsimulation start= disabled
sc config StiSvc start= disabled
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d 00000004 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WalletService" /v "Start" /t REG_DWORD /d 00000004 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc" /v Start /t REG_DWORD /d 00000004 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" /v Start /t REG_DWORD /d 00000004 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /v Start /t REG_DWORD /d 00000004 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" /v Start /t REG_DWORD /d 00000004 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WMPNetworkSvc" /v "Start" /t REG_DWORD /d 00000004 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\autotimesvc" /v "Start" /t REG_DWORD /d 00000004 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\autotimesvc" /v "Start" /t REG_DWORD /d 00000004 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService" /v Start /t REG_DWORD /d 00000004 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\autotimesvc" /v "Start" /t REG_DWORD /d 00000004 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService" /v Start /t REG_DWORD /d 00000004 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /v Start /t REG_DWORD /d 00000004 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v Start /t REG_DWORD /d 00000004 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BcastDVRUserService" /v Start /t REG_DWORD /d 00000004 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc" /v Start /t REG_DWORD /d 00000004 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc" /v Start /t REG_DWORD /d 00000004 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc" /v Start /t REG_DWORD /d 00000004 /f
sc config edgeupdatem start= disabled
sc config MicrosoftEdgeElevationService start= disabled
sc config ALG start= disabled
sc config QWAVE start= disabled
sc config IpxlatCfgSvc start= disabled
sc config icssvc start= disabled
sc config iphlpsvc start= disabled
sc config DusmSvc start= disabled
sc config MapsBroker start= disabled
sc config edgeupdate start= disabled
sc config FrameServer start= disabled
sc config SensorService start= disabled
sc config shpamsvc start= disabled
sc config svsvc start= disabled
sc config SysMain start= disabled
sc config MSiSCSI start= disabled
sc config Netlogon start= disabled
sc config CscService start= disabled
sc config ssh-agent start= disabled
sc config AppReadiness start= disabled
sc config AppXSVC start= disabled
sc config tzautoupdate start= disabled
sc config NfsClnt start= disabled
sc config WbioSrvc start= disabled
sc config wisvc start= disabled
sc config defragsvc start= disabled
sc config VaultSvc start= disabled
sc config SharedRealitySvc start= disabled
sc config RetailDemo start= disabled
sc config lltdsvc start= disabled
sc config TrkWks start= disabled
sc config TokenBroker start= disabled
sc config AppIDSvc start= disabled
Echo.
Echo. [101;41mThe services has been disabled.[0m

Echo.
Echo.
Echo.
Echo. [101;43mPlease Restart Your Computer After The Script Done![0m
Echo.
Echo.
Echo.
Pause.
