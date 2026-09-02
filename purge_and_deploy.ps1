$root = "F:\AEGIS"
$dryRun = $false

function Remove-Safe {
    param([string]$Path, [string]$Description)
    if (Test-Path $Path) {
        if ($dryRun) {
            Write-Host "[DRY-RUN] Supprimerait : $Description ($Path)" -ForegroundColor Yellow
        } else {
            Remove-Item -Path $Path -Recurse -Force
            Write-Host "[OK] Supprime : $Description ($Path)" -ForegroundColor Green
        }
    } else {
        Write-Host "[SKIP] Introuvable : $Description" -ForegroundColor DarkGray
    }
}

Write-Host "=== Execution du nettoyage réel de la structure AEGIS v2 ===" -ForegroundColor Cyan
Write-Host "Mode Dry-Run : $dryRun" -ForegroundColor Cyan
Write-Host ""

# 1. Suppression effective du dossier Android racine redondant
$redundantAndroid = "$root\android"
Remove-Safe -Path $redundantAndroid -Description "Dossier Android racine redondant"

# 2. Purge du FileProvider (res/xml) - conforme Zero-URI
Remove-Safe -Path "$root\aegis_app\android\app\src\main\res\xml" -Description "Dossier res/xml (FileProvider)"

# 3. Caches et artefacts de compilation
$buildDirs = @(
    "$root\aegis-core\target",
    "$root\aegis_app\build",
    "$root\aegis_app\.dart_tool",
    "$root\aegis_app\android\.gradle",
    "$root\aegis_app\android\.kotlin",
    "$root\aegis_app\android\app\.cxx",
    "$root\aegis_app\linux\flutter\ephemeral",
    "$root\aegis_app\windows\flutter\ephemeral",
    "$root\__pycache__"
)
foreach ($dir in $buildDirs) {
    Remove-Safe -Path $dir -Description "Cache build"
}

# 4. Nettoyage ciblé des fichiers temporaires (avec exclusion du CDC)
$tempPatterns = @("tree*.txt", "project_structure.txt", "commande de lancement*.txt")
$excludedDocs = @("*Cahier des Charges*.docx", "*CDC*.docx", "*Specification*.docx")

Get-ChildItem -Path $root -File | Where-Object {
    $file = $_
    $isTemp = $tempPatterns | Where-Object { $file.Name -like $_ }
    $isExcluded = $excludedDocs | Where-Object { $file.Name -like $_ }
    
    $isTemp -and -not $isExcluded
} | ForEach-Object {
    if ($dryRun) {
        Write-Host "[DRY-RUN] Supprimerait : $($_.Name)" -ForegroundColor Yellow
    } else {
        Remove-Item -Path $_.FullName -Force
        Write-Host "[OK] Supprime : $($_.Name)" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Nettoyage termine avec succes." -ForegroundColor Cyan