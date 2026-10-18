# test_forensic_purge.ps1
# P3 — Test forensique post-purge (dd).
# PRÉREQUIS : Device rooté ou Émulateur avec `adb root` activé.

$ErrorActionPreference = "Stop"
$adb = "D:\Android\Sdk\platform-tools\adb.exe"
$package = "com.example.aegis_app"
$pattern = "AEGIS_FORENSIC_TEST_PATTERN_1234567890"

Write-Host "=== ÉTAPE 0 : Vérification ADB ===" -ForegroundColor Cyan
$devices = & $adb devices
if ($devices -notmatch "device") {
    Write-Host "ERREUR : Aucun device ADB connecté." -ForegroundColor Red
    exit 1
}

Write-Host "=== ÉTAPE 1 : Création du payload (10 Mo) ===" -ForegroundColor Cyan
# On pousse un fichier de test dans le sandbox de l'app
$dummyContent = $pattern + ("A" * 1024)
& $adb shell "run-as $package sh -c 'echo -n $dummyContent > files/forensic_test.dat'"
& $adb shell "run-as $package sh -c 'dd if=/dev/zero bs=1M count=10 >> files/forensic_test.dat'"
Write-Host "Fichier de 10 Mo créé dans l'app."

Write-Host "=== ÉTAPE 2 : Lancement du Wipe (Manuel) ===" -ForegroundColor Yellow
Write-Host "ACTION : Lancez le Wipe (Panic Purge) sur le téléphone maintenant."
Read-Host "Appuyez sur Entrée une fois le wipe effectué..."

Write-Host "=== ÉTAPE 3 : fstrim forcé par le système ===" -ForegroundColor Cyan
# Le fstrim nécessite root sur /data
& $adb shell "su -c 'fstrim -v /data'"

Write-Host "=== ÉTAPE 4 : Dump de la partition /data (50 Mo) ===" -ForegroundColor Cyan
$dumpFile = "/sdcard/forensic_dump.img"
& $adb shell "su -c 'dd if=/dev/block/by-name/userdata of=$dumpFile bs=1M count=50'"

Write-Host "=== ÉTAPE 5 : Extraction et recherche ===" -ForegroundColor Cyan
$localDump = "F:\AEGIS\forensic_dump.img"
& $adb pull $dumpFile $localDump | Out-Null

# Recherche du pattern
$bytes = [System.IO.File]::ReadAllBytes($localDump)
$searchBytes = [System.Text.Encoding]::ASCII.GetBytes($pattern)
$found = $false
for ($i = 0; $i -lt ($bytes.Length - $searchBytes.Length); $i++) {
    $match = $true
    for ($j = 0; $j -lt $searchBytes.Length; $j++) {
        if ($bytes[$i + $j] -ne $searchBytes[$j]) { $match = $false; break }
    }
    if ($match) { $found = $true; break }
}

if ($found) {
    Write-Host "❌ ÉCHEC : Le pattern est encore présent !" -ForegroundColor Red
} else {
    Write-Host "✅ SUCCÈS : P3 VALIDÉ. Le pattern a disparu de la partition." -ForegroundColor Green
}

# Cleanup
& $adb shell "rm $dumpFile"
& $adb shell "run-as $package rm files/forensic_test.dat"
Remove-Item $localDump -Force -ErrorAction SilentlyContinue