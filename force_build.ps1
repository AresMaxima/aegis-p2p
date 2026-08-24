$ErrorActionPreference = "Stop"

Write-Host "=== DETECTION DU NDK SUR D: ===" -ForegroundColor Cyan
$ndkBase = "D:\Android\Sdk\ndk" 
$ndkPath = (Get-ChildItem $ndkBase | Select-Object -First 1).FullName
$ndkBin = "$ndkPath\toolchains\llvm\prebuilt\windows-x86_64\bin"

$clangExe = "$ndkBin\clang.exe"
$arExe = "$ndkBin\llvm-ar.exe"

if (-not (Test-Path $clangExe)) {
    Write-Host "[ERREUR] clang.exe introuvable dans $ndkBin" -ForegroundColor Red
    exit 1
}

Write-Host "=== CONFIGURATION ANTI-BUG CMD (CARGO TOML) ===" -ForegroundColor Yellow
$cargoDir = "F:\AEGIS\aegis-core\.cargo"
if (-not (Test-Path $cargoDir)) { New-Item -ItemType Directory -Path $cargoDir | Out-Null }

# On remplace les antislashs par des slashs pour le format TOML
$clangToml = $clangExe -replace '\\', '/'
$arToml = $arExe -replace '\\', '/'

$configToml = @"
[target.aarch64-linux-android]
linker = "$clangToml"
ar = "$arToml"
rustflags = ["-C", "link-arg=--target=aarch64-linux-android27"]
"@
Set-Content -Path "$cargoDir\config.toml" -Value $configToml -Encoding UTF8

# Variables pour compiler les dépendances C (comme ring)
$env:PATH = "$ndkBin;D:\ARES_PROJECT\jdk-17.0.10+7\bin;D:\flutter\bin;$env:PATH"
$env:CC_aarch64_linux_android = $clangExe
$env:CFLAGS_aarch64_linux_android = "--target=aarch64-linux-android27"
$env:AR_aarch64_linux_android = $arExe

Set-Location "F:\AEGIS\aegis-core"

Write-Host "=== COMPILATION RUST === " -ForegroundColor Cyan
cargo build --target aarch64-linux-android --release

Write-Host "=== SYNCHRONISATION DU BINAIRE ===" -ForegroundColor Cyan
Copy-Item -Force "target\aarch64-linux-android\release\libaegis_core.so" "..\aegis_app\android\app\src\main\jniLibs\arm64-v8a\libaegis_core.so"

Write-Host "=== COMPILATION FLUTTER ===" -ForegroundColor Cyan
Set-Location "F:\AEGIS\aegis_app"
flutter build apk --release --split-per-abi

Write-Host "=== AUDIT ET SCELLEMENT ===" -ForegroundColor Cyan
powershell -ExecutionPolicy Bypass -File "F:\AEGIS\audit_and_seal.ps1"