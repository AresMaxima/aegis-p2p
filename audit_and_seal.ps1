# Script d Audit Automatise et de Scellement Cryptographique AEGIS v1.3.0
$ErrorActionPreference = "Stop"
Set-Location "F:\AEGIS"

$timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss UTC")
$reportFile = "F:\AEGIS\AUDIT_MANIFEST.json"
$apkPath = "F:\AEGIS\aegis_app\build\app\outputs\flutter-apk\app-arm64-v8a-release.apk"
$soPath = "F:\AEGIS\aegis_app\android\app\src\main\jniLibs\arm64-v8a\libaegis_core.so"

Write-Host "=== DEBUT DE L AUDIT DE CONFORMITE INTRUSIF AEGIS v1.3.0 ===" -ForegroundColor Cyan

$checks = [ordered]@{}
$globalPassed = $true

function Clean-Code($content) {
    if (-not $content) { return "" }
    $noBlock = $content -replace '(?s)/\*.*?\*/', ''
    return $noBlock -replace '//.*', ''
}

# 1. Audit Binaire APK Release
if (Test-Path $apkPath) {
    $apkHash = (Get-FileHash -Path $apkPath -Algorithm SHA256).Hash.ToLower()
    $checks["apk_build"] = [ordered]@{ "status" = "PASSED"; "hash_sha256" = $apkHash; "path" = $apkPath }
} else {
    $checks["apk_build"] = [ordered]@{ "status" = "FAILED"; "error" = "APK release introuvable" }
    $globalPassed = $false
}

# 2. Audit Binaire Native .so & Inspection des symboles FFI (Correction PS 5.1)
if (Test-Path $soPath) {
    $soHash = (Get-FileHash -Path $soPath -Algorithm SHA256).Hash.ToLower()
    $soBytes = [System.IO.File]::ReadAllBytes($soPath)
    $encoding = [System.Text.Encoding]::GetEncoding("ISO-8859-1")
    $soText = $encoding.GetString($soBytes)
    
    $symIngest = $soText.Contains("aegis_ingest_file_zero_disk")
    $symPurge  = $soText.Contains("aegis_purge_ram_buffer")
    $symPanic  = $soText.Contains("aegis_panic_silent_burn")
    $soValid   = $symIngest -and $symPurge -and $symPanic

    $checks["native_rust_library"] = [ordered]@{
        "hash_sha256" = $soHash
        "exported_aegis_ingest" = $symIngest
        "exported_aegis_purge"  = $symPurge
        "exported_aegis_panic"  = $symPanic
        "status" = if ($soValid) { "PASSED" } else { "FAILED" }
    }
    if (-not $soValid) { $globalPassed = $false }
} else {
    $checks["native_rust_library"] = [ordered]@{ "status" = "FAILED"; "error" = "libaegis_core.so introuvable" }
    $globalPassed = $false
}

# 3. Audit MainActivity.kt (Hardening Android Natif)
$ktPath = "F:\AEGIS\aegis_app\android\app\src\main\kotlin\com\example\aegis_app\MainActivity.kt"
if (Test-Path $ktPath) {
    $ktClean = Clean-Code (Get-Content $ktPath -Raw)
    $ktSecure = $ktClean -match "FLAG_SECURE"
    $ktPause  = $ktClean -match "override fun onPause\(\)"
    $ktStop   = $ktClean -match "override fun onStop\(\)"
    $ktFocus  = $ktClean -match "override fun onWindowFocusChanged\("
    
    $ktKillCount = ([regex]::Matches($ktClean, "Process\.killProcess")).Count
    $ktExitCount = ([regex]::Matches($ktClean, "System\.exit\(137\)")).Count
    $ktKill   = ($ktKillCount -ge 3) -and ($ktExitCount -ge 3)
    $ktPassed = $ktSecure -and $ktPause -and $ktStop -and $ktFocus -and $ktKill

    $checks["native_android_hardening"] = [ordered]@{
        "flag_secure_enforced" = $ktSecure
        "on_pause_overridden"  = $ktPause
        "on_stop_overridden"   = $ktStop
        "on_focus_overridden"  = $ktFocus
        "tri_kill_switch_137"  = $ktKill
        "status" = if ($ktPassed) { "PASSED" } else { "FAILED" }
    }
    if (-not $ktPassed) { $globalPassed = $false }
} else {
    $checks["native_android_hardening"] = [ordered]@{ "status" = "FAILED"; "error" = "MainActivity.kt introuvable" }
    $globalPassed = $false
}

# 4. Audit main.dart (Coupe-Circuit Lifecycle Flutter)
$mainPath = "F:\AEGIS\aegis_app\lib\main.dart"
if (Test-Path $mainPath) {
    $mainClean = Clean-Code (Get-Content $mainPath -Raw)
    $dInactive = $mainClean -match "AppLifecycleState.inactive"
    $dPaused   = $mainClean -match "AppLifecycleState.paused"
    $dDetached = $mainClean -match "AppLifecycleState.detached"
    $dExit137  = $mainClean -match "exit\(137\)"
    $dObserver = $mainClean -match "with WidgetsBindingObserver"
    $mainPassed = $dInactive -and $dPaused -and $dDetached -and $dExit137 -and $dObserver

    $checks["flutter_lifecycle_kill"] = [ordered]@{
        "widgets_binding_observer" = $dObserver
        "state_inactive_intercept" = $dInactive
        "state_paused_intercept"   = $dPaused
        "state_detached_intercept" = $dDetached
        "exit_137_call"            = $dExit137
        "status" = if ($mainPassed) { "PASSED" } else { "FAILED" }
    }
    if (-not $mainPassed) { $globalPassed = $false }
} else {
    $checks["flutter_lifecycle_kill"] = [ordered]@{ "status" = "FAILED"; "error" = "main.dart introuvable" }
    $globalPassed = $false
}

# 5. Audit blind_viewer.dart (Zero-Heap Dart & Fix v11)
$bvPath = "F:\AEGIS\aegis_app\lib\views\blind_viewer.dart"
if (Test-Path $bvPath) {
    $bvClean = Clean-Code (Get-Content $bvPath -Raw)
    $zeroHeap = $bvClean -match "withData:\s*false"
    $ffiIngest = $bvClean -match "aegis_ingest_file_zero_disk"
    $fpDirect  = $bvClean -match "fp\.FilePicker\.pickFiles"
    $noLegacy  = -not ($bvClean -match "fp\.FilePicker\.platform")
    $bvPassed  = $zeroHeap -and $ffiIngest -and $fpDirect -and $noLegacy

    $checks["blind_viewer_opsec"] = [ordered]@{
        "zero_heap_dart_enforced" = $zeroHeap
        "ffi_rust_link_active"    = $ffiIngest
        "file_picker_v11_direct"  = $fpDirect
        "no_legacy_platform_call" = $noLegacy
        "status" = if ($bvPassed) { "PASSED" } else { "FAILED" }
    }
    if (-not $bvPassed) { $globalPassed = $false }
} else {
    $checks["blind_viewer_opsec"] = [ordered]@{ "status" = "FAILED"; "error" = "blind_viewer.dart introuvable" }
    $globalPassed = $false
}

# 6. Audit Profil Release Rust (Cargo.toml)
$cargoPath = "F:\AEGIS\aegis-core\Cargo.toml"
if (Test-Path $cargoPath) {
    $cargoClean = Clean-Code (Get-Content $cargoPath -Raw)
    $panicAbort = $cargoClean -match 'panic\s*=\s*"abort"'
    $ltoTrue    = $cargoClean -match 'lto\s*=\s*true'
    $stripTrue  = $cargoClean -match 'strip\s*=\s*true'
    $cargoPassed = $panicAbort -and $ltoTrue -and $stripTrue

    $checks["rust_release_profile"] = [ordered]@{
        "panic_abort" = $panicAbort
        "lto_enabled"  = $ltoTrue
        "symbols_stripped" = $stripTrue
        "status" = if ($cargoPassed) { "PASSED" } else { "FAILED" }
    }
    if (-not $cargoPassed) { $globalPassed = $false }
}

# Generation du Rapport JSON Dynamique
$auditReport = [ordered]@{
    "audit_title"   = "AEGIS Deep Security & Specification Audit"
    "version"       = "v1.3.0-P2P-HEAVY"
    "timestamp"     = $timestamp
    "global_status" = if ($globalPassed) { "PASSED" } else { "FAILED" }
    "audit_checks"  = $checks
}

$auditReport | ConvertTo-Json -Depth 5 | Set-Content $reportFile -Encoding UTF8

# Bilan Console
$manifestHash = (Get-FileHash -Path $reportFile -Algorithm SHA256).Hash.ToLower()
Write-Host ""
if ($globalPassed) {
    Write-Host "=== AUDIT REUSSI : TOUS LES CONTROLES SONT VALIDES ===" -ForegroundColor Green
} else {
    Write-Host "=== ECHEC DE L AUDIT : DES ANOMALIES ONT ETE DETECTEES ===" -ForegroundColor Red
}
Write-Host "Rapport ecrit : $reportFile" -ForegroundColor White
Write-Host "EMPREINTE SHA-256 MANIFESTE : $manifestHash" -ForegroundColor Yellow