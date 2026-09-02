# ==============================================================================
# AEGIS FORCE BUILD ENGINE v4.0 (PATHS HARDCODÉS VÉRIFIÉS)
# ==============================================================================
$ErrorActionPreference = "Stop"
$rootDir = $PSScriptRoot
if (-not $rootDir) { $rootDir = Get-Location }

# 1. VERROUILLAGE ET INJECTION DU JDK JAVA
$env:JAVA_HOME = "D:\ARES_PROJECT\jdk-17.0.10+7"
$env:Path      = "D:\ARES_PROJECT\jdk-17.0.10+7\bin;$env:Path"
Write-Host "JAVA_HOME verrouillé : $env:JAVA_HOME" -ForegroundColor Green

# 2. VERROUILLAGE ET INJECTION DE FLUTTER
$env:Path = "D:\flutter\bin;$env:Path"
Write-Host "Flutter verrouillé  : D:\flutter\bin" -ForegroundColor Green

# 3. VERROUILLAGE ET CONFIGURATION DU NDK ANDROID
Write-Host "`n=== CONFIGURATION DU NDK ET CARGO ===" -ForegroundColor Cyan
$ndkBase = "D:\Android\Sdk\ndk"
if (Test-Path $ndkBase) {
    $ndkSub = Get-ChildItem -Path $ndkBase -Directory | Sort-Object Name -Descending | Select-Object -First 1
    $actualNdk = if ($ndkSub) { $ndkSub.FullName } else { $ndkBase }
    $llvmBin = Join-Path $actualNdk "toolchains/llvm/prebuilt/windows-x86_64/bin"
    
    $linkerScript = Join-Path $llvmBin "aarch64-linux-android29-clang.cmd"
    if (-not (Test-Path $linkerScript)) {
        $linkerScript = Join-Path $llvmBin "aarch64-linux-android30-clang.cmd"
    }

    if (Test-Path $linkerScript) {
        $env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = $linkerScript
        $env:CC_aarch64_linux_android = $linkerScript
        $env:AR_aarch64_linux_android = Join-Path $llvmBin "llvm-ar.exe"
        Write-Host "NDK Linker chargé : $linkerScript" -ForegroundColor Green
    }
} else {
    Write-Host "ERREUR : Repertoire NDK introuvable dans D:\Android\Sdk\ndk" -ForegroundColor Red
    exit 1
}

rustup target add aarch64-linux-android | Out-Null

# 4. COMPILATION RUST NATIVE (.SO ARM64)
Write-Host "`n=== COMPILATION RUST NATIVE (ARM64) ===" -ForegroundColor Cyan
Push-Location (Join-Path $rootDir "aegis-core")
try {
    cargo build --target aarch64-linux-android --release
    if ($LASTEXITCODE -ne 0) { throw "Echec de compilation Cargo" }
} finally {
    Pop-Location
}

# 5. SYNCHRONISATION DU BINAIRE NATIVE (.SO)
Write-Host "`n=== SYNCHRONISATION BINAIRE NATIVE (.SO) ===" -ForegroundColor Cyan
$soArm64Target = Join-Path $rootDir "aegis-core/target/aarch64-linux-android/release/libaegis_core.so"
$targetDir = Join-Path $rootDir "aegis_app/android/app/src/main/jniLibs/arm64-v8a"

if (-not (Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force }
if (Test-Path $soArm64Target) {
    Copy-Item -Path $soArm64Target -Destination (Join-Path $targetDir "libaegis_core.so") -Force
    Write-Host "libaegis_core.so copié dans jniLibs/arm64-v8a." -ForegroundColor Green
} else {
    Write-Host "ERREUR : Le binaire .so n'a pas été généré." -ForegroundColor Red
    exit 1
}

# 6. COMPILATION APK FLUTTER RELEASE
Write-Host "`n=== COMPILATION APK FLUTTER RELEASE ===" -ForegroundColor Cyan
Push-Location (Join-Path $rootDir "aegis_app")
try {
    flutter build apk --target-platform android-arm64 --release
    if ($LASTEXITCODE -ne 0) { throw "Échec de compilation Flutter" }
} finally {
    Pop-Location
}

# 7. PASSERELLE DE CONFORMITÉ ET AUDIT
Write-Host "`n=== PASSERELLE DE CONFORMITÉ ET AUDIT ===" -ForegroundColor Cyan
$complianceScript = Join-Path $rootDir "check-compliance.ps1"
if (Test-Path $complianceScript) {
    & powershell -ExecutionPolicy Bypass -File $complianceScript
} else {
    Write-Host "Fichier check-compliance.ps1 introuvable." -ForegroundColor Red
    exit 1
}