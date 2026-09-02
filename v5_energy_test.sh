#!/bin/bash
echo "===================================================="
echo "  AEGIS v2.3 - BENCHMARK ÉNERGÉTIQUE V5 (24 HEURES)  "
echo "===================================================="

echo "[1/3] Réinitialisation des statistiques de batterie du noyau..."
adb shell dumpsys batterystats --reset

echo "[2/3] Basculement en mode débranché (Batterystats Unplugged)..."
adb shell dumpsys battery unplug

echo ""
echo "[3/3] INSTRUCTIONS D'EXÉCUTION SUR 24 HEURES :"
echo "1. Débranchez physiquement le câble USB de l'appareil."
echo "2. Laissez tourner l'application AEGIS en arrière-plan pendant 24h réelles."
echo "3. Demain, rebranchez le téléphone et récupérez le rapport chiffré via :"
echo "   adb shell dumpsys batterystats --checkin > aegis_24h_drain.csv"
echo "===================================================="
