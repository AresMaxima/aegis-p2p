@echo off
setlocal enabledelayedexpansion

:: ==============================================================================
:: AEGIS P2P - AUTOMATED BUILD & OPSEC AUDIT SCRIPT
:: Target Architecture: ARM64-v8a (Android)
:: ==============================================================================

title AEGIS P2P - Build & Verification Pipeline
color 0A

echo ==============================================================================
echo                 AEGIS P2P PROTOCOL - RELEASE BUILD PIPELINE
echo ==============================================================================
echo.

:: 1. DETECT ENVIRONMENT & SETUP PATHS
echo [*] Checking Environment Dependencies...

:: CORRECTIF : chemin JDK correct = D:\ARES_PROJECT\jdk-17.0.10+7
if "%JAVA_HOME%"=="" (
    if exist "D:\ARES_PROJECT\jdk-17.0.10+7" (
        set "JAVA_HOME=D:\ARES_PROJECT\jdk-17.0.10+7"
        echo [+] JAVA_HOME set to %JAVA_HOME%
    ) else (
        echo [!] ERROR: JAVA_HOME not defined and JDK not found at D:\ARES_PROJECT\jdk-17.0.10+7
        pause
        exit /b 1
    )
) else (
    echo [+] JAVA_HOME is configured: %JAVA_HOME%
)

:: Ajoute JAVA_HOME\bin au PATH
set "PATH=%JAVA_HOME%\bin;%PATH%"

set "FLUTTER_BIN="
if exist "D:\flutter\bin\flutter.bat" (
    set "FLUTTER_BIN=D:\flutter\bin\flutter.bat"
) else (
    where flutter >nul 2>nul
    if !errorlevel! equ 0 (
        set "FLUTTER_BIN=flutter"
    )
)

if "%FLUTTER_BIN%"=="" (
    echo [!] ERROR: Flutter SDK not found in PATH or D:\flutter\bin.
    pause
    exit /b 1
)
echo [+] Flutter SDK Path: %FLUTTER_BIN%

set "APP_DIR=F:\AEGIS\aegis_app"
if not exist "%APP_DIR%" (
    if exist ".\aegis_app" (
        set "APP_DIR=.\aegis_app"
    ) else if exist ".\pubspec.yaml" (
        set "APP_DIR=."
    )
)

cd /d "%APP_DIR%"
if not exist "pubspec.yaml" (
    echo [!] ERROR: %APP_DIR% is not a valid Flutter project.
    pause
    exit /b 1
)
echo [+] Working Directory: %CD%
echo.

:: 2. DEPENDENCY SANITIZATION
echo ==============================================================================
echo [*] Step 1/4: Fetching dependencies...
echo ==============================================================================
call "%FLUTTER_BIN%" pub get
echo.

:: 3. COMPILATION
echo ==============================================================================
echo [*] Step 2/4: Compiling Hardened ARM64 Release APK...
echo ==============================================================================
call "%FLUTTER_BIN%" build apk --release --target-platform android-arm64
if !errorlevel! neq 0 (
    echo [!] CRITICAL ERROR: Compilation failed!
    pause
    exit /b 1
)
echo.

:: 4. AUDIT & HASH EXTRACTION
echo ==============================================================================
echo [*] Step 3/4: Extracting Cryptographic Signature (SHA-256)...
echo ==============================================================================

:: CORRECTIF : sans --split-per-abi, l'APK est app-release.apk (pas app-arm64-v8a-release.apk)
set "APK_PATH=build\app\outputs\flutter-apk\app-release.apk"

if not exist "%APK_PATH%" (
    echo [!] ERROR: APK not found at %APK_PATH%
    pause
    exit /b 1
)

for /f "skip=1 tokens=*" %%A in ('certutil -hashfile "%APK_PATH%" SHA256 ^| findstr /v "CertUtil"') do (
    set "HASH=%%A"
    goto :hash_done
)
:hash_done

set "HASH=%HASH: =%"

echo.
echo ==============================================================================
echo                       OFFICIAL BUILD AUDIT SUMMARY
echo ==============================================================================
echo [FILE] : app-release.apk
echo [PATH] : %CD%\%APK_PATH%
echo [HASH] : %HASH%
echo ==============================================================================
echo.

echo %date% %time% ^| %HASH% >> build_hash.log
echo [+] Signature written to %CD%\build_hash.log

:: 5. INSTALLATION AUTOMATIQUE SUR LE TELEPHONE
echo.
echo ==============================================================================
echo [*] Step 4/4: Installing on device (SM-G985F)...
echo ==============================================================================

set "ADB=D:\Android\Sdk\platform-tools\adb.exe"

if not exist "%ADB%" (
    echo [!] WARNING: ADB not found at %ADB%. Skip install.
    pause
    exit /b 0
)

"%ADB%" devices | findstr /R "device$" >nul
if !errorlevel! neq 0 (
    echo [!] WARNING: No device detected. Skip install.
    pause
    exit /b 0
)

echo [*] Uninstalling previous version...
"%ADB%" uninstall com.example.aegis_app

echo [*] Installing new version...
"%ADB%" install "%CD%\%APK_PATH%"

echo.
echo ==============================================================================
echo [*] Installed version:
"%ADB%" shell dumpsys package com.example.aegis_app | findstr "versionCode primaryCpuAbi lastUpdateTime"
echo ==============================================================================

echo.
echo [READY FOR FIELD TEST]
pause