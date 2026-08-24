@echo off
:: 1. Detection automatique du NDK et du compilateur Clang
for /d %%i in ("%LOCALAPPDATA%\Android\Sdk\ndk\*") do set "NDK_PATH=%%i"
set "NDK_BIN=%NDK_PATH%\toolchains\llvm\prebuilt\windows-x86_64\bin"
for %%f in ("%NDK_BIN%\aarch64-linux-android*-clang.cmd") do set "CLANG_CMD=%%f"

:: 2. Injection des variables d'environnement NDK et Java
set "JAVA_HOME=D:\ARES_PROJECT\jdk-17.0.10+7"
set "PATH=%NDK_BIN%;%JAVA_HOME%\bin;D:\flutter\bin;%PATH%"
set "CC_aarch64_linux_android=%CLANG_CMD%"
set "AR_aarch64_linux_android=%NDK_BIN%\llvm-ar.exe"
set "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=%CLANG_CMD%"

echo === [1/4] COMPILATION DU NOYAU RUST (libaegis_core.so) ===
cd /d F:\AEGIS\aegis-core
cargo build --target aarch64-linux-android --release
if %ERRORLEVEL% NEQ 0 (
    echo [ERREUR] La compilation Rust a echoue.
    exit /b %ERRORLEVEL%
)

echo === [2/4] SYNCHRONISATION DU BINAIRE NATIVE .SO ===
copy /Y target\aarch64-linux-android\release\libaegis_core.so ..\aegis_app\android\app\src\main\jniLibs\arm64-v8a\libaegis_core.so

echo === [3/4] BUILD DE L'APK RELEASE FLUTTER ===
cd /d F:\AEGIS\aegis_app
call flutter build apk --release --split-per-abi

echo === [4/4] EXECUTION DE L'AUDIT AUTOMATISE ===
powershell -ExecutionPolicy Bypass -File "F:\AEGIS\audit_and_seal.ps1"