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

if "%JAVA_HOME%"=="" (
    if exist "D:\jdk\jdk-17.0.10+7" (
        set "JAVA_HOME=D:\jdk\jdk-17.0.10+7"
        echo [+] Environment Variable JAVA_HOME set to D:\jdk\jdk-17.0.10+7
    ) else (
        echo [!] ERROR: JAVA_HOME is not defined and default JDK was not found.
        pause
        exit /b 1
    )
) else (
    echo [+] JAVA_HOME is configured: %JAVA_HOME%
)

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
    echo [!] ERROR: Flutter SDK executable not found in PATH or D:\flutter\bin.
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
    echo [!] ERROR: Directory %APP_DIR% is not a valid Flutter project.
    pause
    exit /b 1
)
echo [+] Working Directory: %CD%
echo.

:: 2. DEPENDENCY SANITIZATION
echo ==============================================================================
echo [*] Step 1/3: Fetching and Cleaning Dependencies...
echo ==============================================================================
call "%FLUTTER_BIN%" pub get
if !errorlevel! neq 0 (
    echo [!] Warning: pub get encountered issues. Attempting repair with mobile_scanner...
    call "%FLUTTER_BIN%" pub add mobile_scanner
    call "%FLUTTER_BIN%" pub get
)
echo.

:: 3. COMPILATION
echo ==============================================================================
echo [*] Step 2/3: Compiling Hardened ARM64 Release APK...
echo ==============================================================================
call "%FLUTTER_BIN%" build apk --release --target-platform android-arm64 --split-per-abi
if !errorlevel! neq 0 (
    echo [!] CRITICAL ERROR: Compilation failed!
    pause
    exit /b 1
)
echo.

:: 4. AUDIT & HASH EXTRACTION
echo ==============================================================================
echo [*] Step 3/3: Extracting Cryptographic Signature (SHA-256)...
echo ==============================================================================

set "APK_PATH=build\app\outputs\flutter-apk\app-arm64-v8a-release.apk"

if not exist "%APK_PATH%" (
    echo [!] ERROR: APK file not found at expected path: %APK_PATH%
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
echo [FILE] : app-arm64-v8a-release.apk
echo [PATH] : %CD%\%APK_PATH%
echo [HASH] : %HASH%
echo ==============================================================================
echo.

echo %date% %time% ^| %HASH% >> build_hash.log
echo [+] Signature written to %CD%\build_hash.log

echo.
echo [SUCCESS] AEGIS P2P build pipeline completed with 0 errors.
pause