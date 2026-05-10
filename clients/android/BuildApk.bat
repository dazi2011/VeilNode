@echo off
rem One-click debug APK builder for VeilNode Android (Windows host).
rem Requirements: JDK 17+ on PATH, Gradle on PATH, Android SDK at ANDROID_HOME or %LOCALAPPDATA%\Android\Sdk.
setlocal enabledelayedexpansion
set "HERE=%~dp0"
set "ROOT=%HERE%..\.."
set "PROJECT=%ROOT%\clients\android"
if "%VEIL_APK_DIST%"=="" set "VEIL_APK_DIST=%ROOT%\dist\android"
if not exist "%VEIL_APK_DIST%" mkdir "%VEIL_APK_DIST%"

where gradle >nul 2>&1
if errorlevel 1 (
  echo error: gradle not found on PATH
  exit /b 1
)

if "%ANDROID_HOME%"=="" (
  if exist "%LOCALAPPDATA%\Android\Sdk" (
    set "ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk"
    set "ANDROID_SDK_ROOT=%LOCALAPPDATA%\Android\Sdk"
  )
)

pushd "%PROJECT%"
gradle :app:assembleDebug --no-daemon --console=plain
if errorlevel 1 (
  popd
  exit /b 1
)
popd

set "APK=%PROJECT%\app\build\outputs\apk\debug\app-debug.apk"
if not exist "%APK%" (
  echo error: gradle finished but app-debug.apk was not produced
  exit /b 1
)
copy /Y "%APK%" "%VEIL_APK_DIST%\VeilNode-Android-debug.apk" >nul
echo Built: %VEIL_APK_DIST%\VeilNode-Android-debug.apk
echo Install: adb install -r "%VEIL_APK_DIST%\VeilNode-Android-debug.apk"
