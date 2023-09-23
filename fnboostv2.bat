@echo off
title Nao feche essa janela!
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR\FSEBehavior" /v EnableFSEForFullscreenApplications /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteLauncher.exe" /v "PriorityClass" /d "High" /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe" /v "PriorityClass" /d "High" /t REG_DWORD /f
wmic process where name="FortniteClient-Win64-Shipping.exe" CALL setpriority 128
wmic process where name="FortniteClient-Win64-Shipping_BE.exe" CALL setpriority 128
wmic process where name="FortniteLauncher.exe" CALL setpriority 128
taskkill /F /IM EpicGamesLauncher.exe
taskkill /F /IM spoolsv.exe
taskkill /F /IM spoolsv.exe
taskkill /F /IM WmiPrvSE.exe
taskkill /F /IM WmiPrvSE.exe
taskkill /F /IM GameBar.exe 
taskkill /F /IM GameBarFTServer.exe
taskkill /F /IM GameBarPresenceWriter.exe 
taskkill /F /IM gamingservices.exe
taskkill /F /IM gamingservicesnet.exe
taskkill /F /IM LMIGuardianSvc.exe
taskkill /F /IM GoogleCrashHandler.exe
taskkill /F /IM GoogleCrashHandler64.exe
taskkill /F /IM MonectServer.exe
taskkill /F /IM MonectServerService.exe
taskkill /F /IM explorer.exe
taskkill /F /IM explorer.exe
taskkill /F /IM amdfendrsr.exe
taskkill /F /IM atiesrxx.exe
taskkill /F /IM nvcontainer.exe
taskkill /F /IM NVDisplay.Container.exe
taskkill /F /IM NVIDIA Web Helper.exe
net stop InstallService
net stop bthserv
net stop KeyIso
net stop LanmanServer
net stop MonectServerService
net stop TabletInputService
net stop TimeBrokerSvc
net stop CDPUserSvc_6126d
net stop cbdhsvc_6126d
net stop PhoneSvc
net stop OneSyncSvc_482e6
net stop NcdAutoSetup
net stop EventSystem
net stop cbdhsvc_482e6
net stop Themes
net stop fax
net stop Spooler
net stop wuauserv
net stop GamingServices
net stop GamingServicesNet
net stop WSearch
net stop AMD Crash Defender Service
net stop AMD External Events Utility
net stop NvContainerLocalSystem
net stop NVDisplay.ContainerLocalSystem
net stop FvSvc
takeown /f "%WinDir%\System32\GameBarPresenceWriter.exe" /a
takeown /f "%WinDir%\System32\mobsync.exe" /a
takeown /f "%WinDir%\System32\HelpPane.exe" /a
icacls "%WinDir%\System32\mobsync.exe" /grant:r Administrators:F /c
icacls "%WinDir%\System32\HelpPane.exe" /grant:r Administrators:F /c
icacls "%WinDir%\System32\GameBarPresenceWriter.exe" /grant:r Administrators:F /c
TASKKILL /t /f /im GameBarPresenceWriter.exe > NUL 2>&1 
TASKKILL /t /f /im mobsync.exe > NUL 2>&1 
TASKKILL /t /f /im HelpPane.exe > NUL 2>&1 
del "%WinDir%\System32\GameBarPresenceWriter.exe" /s /f /q > NUL 2>&1
del "%WinDir%\System32\mobsync.exe" /s /f /q > NUL 2>&1
del "%WinDir%\System32\HelpPane.exe" /s /f /q > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "DisableVidMemVBs" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "MMX Fast Path" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "FlipNoVsync" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "SoftwareOnly" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d "1" /f 
Reg add %%r /v "AutoDisableGigabit" /t REG_SZ /d "0" /f 
Reg add %%r /v "EnableGreenEthernet" /t REG_SZ /d "0" /f 
Reg add %%r /v "GigaLite" /t REG_SZ /d "0" /f 
Reg add %%r /v "PowerSavingMode" /t REG_SZ /d "0" /f 
reg add "HKCU\Control Panel\Desktop" /v "Visual Effects" /d "0" /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\AutoUpdate" /v "AUOptions" /d "3" /t REG_DWORD /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\ActiveScheme\PowerSettings" /v "DiskTimeOut" /d "0" /t REG_DWORD /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\ActiveScheme\PowerSettings" /v "ScreenOffTimeout" /d "0" /t REG_DWORD /f
cls
Echo Deseja desinstalar apps do windows?
Echo Esse procedimento precisa ser feito apenas uma vez
SET /P choice=  [101;42mS / N:[0m  
IF /I "%choice%"=="S" goto apply
IF /I "%choice%"=="N" goto next
:apply
@powershell "Get-AppxPackage *3dbuilder* | Remove-AppxPackage"
@powershell "Get-AppxPackage *sway* | Remove-AppxPackage"
@powershell "Get-AppxPackage *messaging* | Remove-AppxPackage"
@powershell "Get-AppxPackage *zunemusic* | Remove-AppxPackage"
@powershell "Get-AppxPackage *windowsalarms* | Remove-AppxPackage"
@powershell "Get-AppxPackage *officehub* | Remove-AppxPackage"
@powershell "Get-AppxPackage *skypeapp* | Remove-AppxPackage"
@powershell "Get-AppxPackage *getstarted* | Remove-AppxPackage"
@powershell "Get-AppxPackage *windowsmaps* | Remove-AppxPackage"
@powershell "Get-AppxPackage *solitairecollection* | Remove-AppxPackage"
@powershell "Get-AppxPackage *bingfinance* | Remove-AppxPackage"
@powershell "Get-AppxPackage *zunevideo* | Remove-AppxPackage"
@powershell "Get-AppxPackage *bingnews* | Remove-AppxPackage"
@powershell "Get-AppxPackage *people* | Remove-AppxPackage"
@powershell "Get-AppxPackage *windowsphone* | Remove-AppxPackage"
@powershell "Get-AppxPackage *bingsports* | Remove-AppxPackage"
@powershell "Get-AppxPackage *soundrecorder* | Remove-AppxPackage"
@powershell "Get-AppxPackage *phone* | Remove-AppxPackage"
@powershell "Get-AppxPackage *windowsdvdplayer* | Remove-AppxPackage"
@powershell "Get-AppxPackage  *disney* | Remove-AppxPackage"
@powerShell "Get-AppxPackage *ShazamEntertainmentLtd.Shazam* | Remove-AppxPackage"
@powershell "Get-AppxPackage 'king.com.CandyCrushSaga' | Remove-AppxPackage"
@powerShell "Get-AppxPackage 'king.com.CandyCrushSodaSaga' | Remove-AppxPackage"
@powershell "Get-AppxPackage 'D5EA27B7.Duolingo-LearnLanguagesforFree' | Remove-AppxPackage"
@powershell "Get-AppxPackage 'Microsoft.Advertising.Xaml' | Remove-AppxPackage"
@powershell "Get-AppxPackage 'Microsoft.Office.OneNote' | Remove-AppxPackage"
@powershell "Get-AppxPackage 'Microsoft.YourPhone' | Remove-AppxPackage"
cls
goto :next
:next
bcdedit /set useplatformtick yes
bcdedit /set disabledynamictick yes
bcdedit /deletevalue useplatformclock
pnputil /disable-device "ROOT\AMDLOG\0000"
pnputil /disable-device "SWD\MMDEVAPI\MICROSOFTGSWAVETABLESYNTH"
pnputil /disable-device "DISPLAY\VIE2021\5&3333DC31&A&UID261"
pnputil /disable-device "ROOT\COMPOSITEBUS\0000"
pnputil /disable-device "ACPI\PNP0103\2&DABA3FF&0"
pnputil /disable-device "ROOT\VDRVROOT\0000"
pnputil /disable-device "SWD\MSRRAS\MS_NDISWANIPV6"
pnputil /disable-device "SWD\DRIVERENUM\{C3A63EDD-2D27-4B66-B155-5E94B43D926A}#REALTEKAPO&6&33D04FD8&1"
pnputil /disable-device "PCI\VEN_1022&DEV_15DF&SUBSYS_15DF1022&REV_00\4&28056CF2&0&0241"
schtasks /change /disable /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
schtasks /change /disable /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
schtasks /change /disable /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
schtasks /change /disable /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
schtasks /change /disable /tn "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents"
schtasks /change /disable /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
schtasks /change /disable /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
rd /s /q C:\Windows\Prefetch
steam --flushconfig
discord --clear-storage
spotify:clear-cache
vlc --clear-playlist
zoom --clear-cache
teams --clear-cache
del /q "%appdata%\Microsoft\Windows\Recent\*" /s
del /q "%appdata%\Microsoft\Windows\WebCache\*.*" /s
del /S /F /Q C:\Windows\Temp
del /S /F /Q C:\Users\%username%\AppData\Local\Temp
del /S /F /Q C:\Windows\SoftwareDistribution
del /S /F /Q C:\Users\%username%\AppData\LocalLow\Sun\Java\Deployment\cache
attrib -R C:\Users\%username%\AppData\Local\EpicGamesLauncher\Saved\webcache_4430\Cache
del /S /F /Q C:\Users\%username%\AppData\Local\EpicGamesLauncher\Saved\webcache_4430\Cache
cd C:\Program Files\Epic Games\Fortnite\Engine\Binaries\Win64
taskkill /F /IM CrashReportClient.exe
del "CrashReportClient.exe"
cd C:\Users\%username%
deltree /y c:\windows\tempor~1
deltree /y c:\windows\temp
deltree /y c:\windows\tmp
deltree /y c:\windows\ff*.tmp
deltree /y c:\windows\history
deltree /y c:\windows\cookies
deltree /y c:\windows\recent
deltree /y c:\windows\spool\printers
del c:\WIN386.SWP
netsh interface ipv6 disable
netsh interface tcp set global autotuninglevel=normal
netsh advfirewall firewall add rule name="UPnP" protocol=TCP localport=1900 remoteport=1900 action=allow
ipconfig /flushdns
set DNS1=8.8.8.8
set DNS2=9.9.9.9
set DNS3=1.1.1.1
set DNS12=8.8.4.4
set DNS22=149.112.112.112
set DNS32=1.0.0.1

for /f "delims=" %%i in ('ping -n 1 %DNS1%') do (
    set PingDNS1=%%i
)
for /f "delims=" %%i in ('ping -n 1 %DNS2%') do (
    set PingDNS2=%%i
)
for /f "delims=" %%i in ('ping -n 1 %DNS3%') do (
    set PingDNS3=%%i
)

set PING_menor=%PingDNS1%
set DNS_menor=%DNS1%
set DNS_sec=%DNS12%
if "%PingDNS2%" LSS "%PING_menor%" (
    set PING_menor=%PingDNS2%
    set DNS_menor=%DNS2%
    set DNS_sec=%DNS22%
)
if "%PingDNS3%" LSS "%PING_menor%" (
    set PING_menor=%PingDNS3%
    set DNS_menor=%DNS3%
    set DNS_sec=%DNS32%
)

netsh interface ipv4 set dns name="Ethernet" static %DNS_menor% primary
netsh interface IP add DNS name="Ethernet" %DNS_sec% index=2
netsh interface ipv4 set dns name="Wi-Fi" static %DNS_menor% primary
netsh interface IP add DNS name="Wi-Fi" %DNS_sec% index=2
netsh interface ipv4 set dns name="Local Area Connection 1" static %DNS_menor% primary
netsh interface IP add DNS name="Local Area Connection 1" %DNS_sec% index=2
netsh interface ipv4 set dns name="Local Area Connection 2" static %DNS_menor% primary
netsh interface IP add DNS name="Local Area Connection 2" %DNS_sec% index=2
netsh interface ipv4 set dns name="Local Area Connection 3" static %DNS_menor% primary
netsh interface IP add DNS name="Local Area Connection 3" %DNS_sec% index=2
netsh interface ipv4 set dns name="Local Area Connection 4" static %DNS_menor% primary
netsh interface IP add DNS name="Local Area Connection 4" %DNS_sec% index=2
netsh interface ipv4 set dns name="Local Area Connection 5" static %DNS_menor% primary
netsh interface IP add DNS name="Local Area Connection 5" %DNS_sec% index=2

echo A DNS com o menor ping: %DNS_menor%
rd /s /q C:\$Recycle.bin

FOR /F "tokens=1,2*" %%V IN ('bcdedit') DO SET adminTest=%%V
IF (%adminTest%)==(Access) goto noAdmin
for /F "tokens=*" %%G in ('wevtutil.exe el') DO (call :do_clear "%%G")
echo goto theEnd
:do_clear
rem echo clearing %1
wevtutil.exe cl %1
:noAdmin

:loop
   cls
   Title MENU
   Echo M E N U
   Echo 1 Para abrir a area de trabalho
   Echo 2 Para fecha-la novamente
   Echo 3 Para sair do programa
   Echo.
   choice /c 123 /n /m "Escolha uma opcao:"
   if %errorlevel%==1 (
      start "" "%windir%\Explorer.exe"
   ) else if %errorlevel%==2 (
      taskkill /F /IM explorer.exe
      taskkill /F /IM explorer.exe
      taskkill /F /IM explorer.exe
      taskkill /F /IM explorer.exe
   ) else if %errorlevel%==3 (
      start "" "%windir%\Explorer.exe"
      exit
   ) else (
       echo Opcao invalida.
   )

   goto loop