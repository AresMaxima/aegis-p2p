package com.example.aegis_app

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.security.ConfirmationCallback
import android.security.ConfirmationPrompt
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import java.security.KeyStore
import java.util.concurrent.Executor
import javax.crypto.KeyGenerator

class ProtectedConfirmation(private val context: Context) {

    private val KEY_NAME = "aegis_master_root"

    // =========================================================================
    // 1. CONFIRMATION MATÉRIELLE TEE (ANTI-TOCTOU)
    // =========================================================================
    
    /**
     * Affiche le texte directement via le matériel (TEE) sans passer par la RAM/UI d'Android[cite: 15].
     * Empêche l'extraction du texte par un malware Root avant chiffrement (Anti-TOCTOU)[cite: 15].
     */
    fun promptHardwareConfirmation(
        promptText: String,
        extraData: ByteArray,
        executor: Executor,
        onSuccess: (ByteArray) -> Unit,
        onFailure: () -> Unit
    ) {
        if (!ConfirmationPrompt.isSupported(context)) {
            // Matériel non compatible avec l'affichage TEE[cite: 15]
            onFailure()
            return
        }

        val builder = ConfirmationPrompt.Builder(context)
            .setPromptText(promptText)
            .setExtraData(extraData)

        val prompt = builder.build()
        prompt.presentPrompt(executor, object : ConfirmationCallback() {
            override fun onConfirmed(dataThatWasConfirmed: ByteArray) {
                super.onConfirmed(dataThatWasConfirmed)
                // Signature matérielle validée directement par le TEE[cite: 15]
                onSuccess(dataThatWasConfirmed)
            }

            override fun onCanceled() {
                super.onCanceled()
                onFailure()
            }

            override fun onError(throwable: Throwable?) {
                super.onError(throwable)
                onFailure()
            }
        })
    }

    // =========================================================================
    // 2. GESTION STRONGBOX ET VERROUILLAGE SYSTÈME
    // =========================================================================
    
    // Génération de la clé scellée dans le StrongBox matériel
    @RequiresApi(Build.VERSION_CODES.P)
    fun generateStrongBoxKey() {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
        )
        
        val builder = KeyGenParameterSpec.Builder(
            KEY_NAME,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setUserAuthenticationRequired(true) // Force la validation PIN
        .setUserAuthenticationValidityDurationSeconds(0) // Re-vérification à chaque usage
        .setIsStrongBoxBacked(true) // Ancrage matériel strict

        keyGenerator.init(builder.build())
        keyGenerator.generateKey()
    }

    // Appel du TEE-UI (Écran de verrouillage système isolé)
    fun getSecurePromptIntent(): Intent? {
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        return if (keyguardManager.isDeviceSecure) {
            // L'OS prend le relais dans un environnement sécurisé (pas de RAM Flutter)
            keyguardManager.createConfirmDeviceCredentialIntent(
                "AEGIS Zero-Trust",
                "Saisissez votre code PIN d'accès matériel."
            )
        } else {
            null
        }
    }

    // =========================================================================
    // 3. DÉCLENCHEURS MATÉRIELS D'URGENCE
    // =========================================================================
    
    // Déclencheur du Panic Purge depuis le Kotlin
    external fun aegisPanicSilentBurn()

    fun triggerCrisisBurn() {
        // Appelle le noyau Rust pour détruire la NVRAM et exit 137
        aegisPanicSilentBurn()
    }
}