@echo off
:: ==============================================================================
:: AEGIS — build.bat v2 (fix 2026-09-23)
:: Correction : NDK localisé dans D:\Android\Sdk\ndk\ (pas LOCALAPPDATA).
:: Fix C18-bis : échec silencieux si NDK_PATH vide.
:: ==============================================================================

:: 1. Detection du NDK — priorité D:\Android\Sdk\ndk\ (version 27)
set "NDK_PATH=D:\Android\Sdk\ndk\27.0.12077973"
if not exist "%NDK_PATH%" (
    echo [!] NDK 27 absent, fallback vers dernier NDK de D:\Android\Sdk\ndk\
    for /f "delims=" %%i in ('dir /b /ad /o-n "D:\Android\Sdk\ndk\*" 2^>nul') do (
        set "NDK_PATH=D:\Android\Sdk\ndk\%%i"
        goto :ndk_found
    )
    echo [!] NDK absent de D:\Android\Sdk\ndk\, fallback LOCALAPPDATA
    for /f "delims=" %%i in ('dir /b /ad /o-n "%LOCALAPPDATA%\Android\Sdk\ndk\*" 2^>nul') do (
        set "NDK_PATH=%LOCALAPPDATA%\Android\Sdk\ndk\%%i"
        goto :ndk_found
    )
    echo [ERREUR] Aucun NDK trouve. Installez via sdkmanager "ndk;27.0.12077973"
    exit /b 1
)
:ndk_found
echo [+] NDK utilise : %NDK_PATH%

set "NDK_BIN=%NDK_PATH%\toolchains\llvm\prebuilt\windows-x86_64\bin"
if not exist "%NDK_BIN%" (
    echo [ERREUR] Dossier bin du NDK introuvable : %NDK_BIN%
    exit /b 1
)

:: 2. Selection du compilateur clang (API la plus recente disponible)
set "CLANG_CMD="
for %%f in ("%NDK_BIN%\aarch64-linux-android*-clang.cmd") do set "CLANG_CMD=%%f"
if "%CLANG_CMD%"=="" (
    echo [ERREUR] Compilateur aarch64-linux-android*-clang.cmd introuvable dans :
    echo         %NDK_BIN%
    exit /b 1
)
echo [+] Compilateur : %CLANG_CMD%

:: 3. Injection des variables NDK, Java et Cargo
set "JAVA_HOME=D:\ARES_PROJECT\jdk-17.0.10+7"
set "PATH=%NDK_BIN%;%JAVA_HOME%\bin;D:\flutter\bin;D:\aegis_build\cargo\bin;%PATH%"
set "CC_aarch64_linux_android=%CLANG_CMD%"
set "AR_aarch64_linux_android=%NDK_BIN%\llvm-ar.exe"
set "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=%CLANG_CMD%"

echo [+] CC_aarch64_linux_android = %CC_aarch64_linux_android%
echo.

echo === [1/3] COMPILATION DU NOYAU RUST (libaegis_core.so) ===
cd /d F:\AEGIS\aegis-core
"D:\aegis_build\cargo\bin\cargo.exe" build --target aarch64-linux-android --release
if %ERRORLEVEL% NEQ 0 (
    echo [ERREUR] La compilation Rust a echoue.
    exit /b %ERRORLEVEL%
)

echo === [2/3] SYNCHRONISATION DU BINAIRE NATIVE .SO ===
mkdir "..\aegis_app\android\app\src\main\jniLibs\arm64-v8a" 2>nul
copy /Y target\aarch64-linux-android\release\libaegis_core.so ..\aegis_app\android\app\src\main\jniLibs\arm64-v8a\libaegis_core.so

echo === [3/3] BUILD DE L'APK RELEASE FLUTTER ===
cd /d F:\AEGIS\aegis_app
call "D:\flutter\bin\flutter.bat" build apk --release

echo.
echo [BUILD TERMINE]