// lib/services/global_state.dart
//
// État global partagé entre main.dart et les différents écrans.
//
// Contient :
//   • isIntentPendingInDart : flag booléen pour suspendre la purge
//     d'inactivité pendant un flow externe (permission dialog, file
//     picker, caméra, etc.).
//   • externalFlowCounter : compteur pour supporter les flows imbriqués
//     (utile quand un flow en lance un autre).

/// Vrai ssi un flow externe est en cours (compatibilité ascendante).
bool isIntentPendingInDart = false;

/// Compteur de flows externes actifs.
/// Incrémenté avant, décrémenté après chaque flow.
int externalFlowCounter = 0;

/// À appeler AVANT d'ouvrir un flow externe (permission dialog,
/// file picker, caméra, etc.).
void beginExternalFlow() {
  externalFlowCounter++;
  isIntentPendingInDart = true;
}

/// À appeler DANS un `finally` après le flow externe.
void endExternalFlow() {
  if (externalFlowCounter > 0) {
    externalFlowCounter--;
  }
  if (externalFlowCounter == 0) {
    isIntentPendingInDart = false;
  }
}

/// Vrai ssi au moins un flow externe est actif.
/// `UserInactivityWrapper` doit consulter cette fonction au lieu du
/// flag brut pour supporter les flows imbriqués.
bool isExternalFlowActive() =>
    externalFlowCounter > 0 || isIntentPendingInDart;

/// Autres globales existantes (déplacées depuis main.dart).
String activeRamPin = "";
String globalSteganoRamBuffer = "";