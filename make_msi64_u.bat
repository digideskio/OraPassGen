@echo off
SET BUILD_ARCH=x64

SET DIR1=c:\Program Files (x86)\WiX Toolset v3.9\bin
SET DIR2=c:\Program Files\WiX Toolset v3.9\bin
SET DIR3=c:\Program Files\WiX Toolset v3.10\bin
SET DIR4=..\wix-3.10

IF EXIST "%DIR1%"\ SET PATH=%DIR1%;%PATH%
IF EXIST "%DIR2%"\ SET PATH=%DIR2%;%PATH%
IF EXIST "%DIR3%"\ SET PATH=%DIR3%;%PATH%
IF EXIST "%DIR4%"\ SET PATH=%DIR4%;%PATH%

set BUILD_NUMBER=7

IF EXIST "*.p12" (
@echo off
set /p id=Enter Certificate password:
REM echo %id%
signtool sign /v /f "OSD Ivan Brezina.p12" /P %id% ^
  /d "Password tool for Oracle" ^
  /du "https://github.com/ibre5041/OraPassGen" ^
  /t http://timestamp.verisign.com/scripts/timstamp.dll ^
  src\RelWithDebInfo\*.exe src\RelWithDebInfo\*.dll
)

REM for /F "tokens=1,2"  %%t  in ('svn info') do @if "%%t"=="Revision:" set BUILD_NUMBER=%%u
REM echo Build Number: %BUILD_NUMBER%

for /F "tokens=1"  %%t  in ('git describe --long --tags --dirty --always') do set GIT_RELEASE=%%t
REM set GIT_RELEASE=v3.0alpha-30-g8e691f2-dirty
echo %GIT_RELEASE%

REM for /f "tokens=2 delims=- " %%G IN ("%GIT_RELEASE%") DO set BUILD_NUMBER=%%G
echo Build Number: %BUILD_NUMBER%

candle.exe dbpass_user.wxs
light.exe -sice:ICE91 -ext WixUIExtension -o dbpass_user.64bit.msi dbpass_user.wixobj

IF EXIST "*.p12" (
 signtool sign /v /f "OSD Ivan Brezina.p12" /P %id% ^
 /d "Password tool for Oracle" ^
 /du "https://github.com/ibre5041/OraPassGen" ^
 /t http://timestamp.verisign.com/scripts/timstamp.dll *.msi
)

@pause
