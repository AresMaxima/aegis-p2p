package com.example.aegis_app

import android.app.Activity
import android.content.Intent
import androidx.annotation.NonNull
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity: FlutterActivity() {
    companion object {
        // Définition des deux canaux pour maintenir la compatibilité avec votre code Dart[cite: 16]
        private const val KEYSTORE_CHANNEL = "com.aegis/keystore"
        private const val TEE_UI_CHANNEL = "com.aegis.p2p/tee_ui"
    }

    private lateinit var protectedConfirmation: ProtectedConfirmation
    private var pendingResult: MethodChannel.Result? = null

    override fun configureFlutterEngine(@NonNull flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        protectedConfirmation = ProtectedConfirmation(this)

        // =========================================================================
        // 1. CANAL D'ORIGINE : GESTION STRONGBOX[cite: 16]
        // =========================================================================
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, KEYSTORE_CHANNEL).setMethodCallHandler { call, result ->
            if (call.method == "getHardwareSecret") {
                val isVaultEmpty = call.argument<Boolean>("isVaultEmpty") ?: false
                val secret = HardwareKeystore.getHardwareSecret(isVaultEmpty)
                if (secret != null) {
                    result.success(secret)
                } else {
                    result.error("TEE_ERROR", "Échec de génération du secret StrongBox", null)
                }
            } else {
                result.notImplemented()
            }
        }

        // =========================================================================
        // 2. NOUVEAU CANAL : TEE-UI ET DÉCLENCHEUR PANIC PURGE
        // =========================================================================
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, TEE_UI_CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "invokeHardwarePrompt" -> {
                    val intent = protectedConfirmation.getSecurePromptIntent()
                    if (intent != null) {
                        pendingResult = result
                        startActivityForResult(intent, 1001)
                    } else {
                        result.error("UNSECURE_DEVICE", "Aucun PIN système configuré.", null)
                    }
                }
                "triggerPanic" -> {
                    // Si Flutter détecte la saisie de "9999" sur un champ leurre
                    protectedConfirmation.triggerCrisisBurn()
                    result.success(true)
                }
                else -> result.notImplemented()
            }
        }
    }

    // =========================================================================
    // 3. RETOUR DE L'ÉCRAN DE VERROUILLAGE SYSTÈME (PIN)
    // =========================================================================
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1001) {
            if (resultCode == Activity.RESULT_OK) {
                // Le TEE a validé le PIN, on autorise le noyau Rust à dériver la clé
                pendingResult?.success(true)
            } else {
                pendingResult?.error("AUTH_FAILED", "Échec de l'authentification matérielle.", null)
            }
            pendingResult = null
        }
    }
}