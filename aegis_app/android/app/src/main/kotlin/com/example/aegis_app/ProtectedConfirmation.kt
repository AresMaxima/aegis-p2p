package com.example.aegis_app

import android.content.Context
import android.security.ConfirmationCallback
import android.security.ConfirmationPrompt
import java.util.concurrent.Executor

class ProtectedConfirmation(private val context: Context) {

    /**
     * Affiche le texte directement via le matériel (TEE) sans passer par la RAM/UI d'Android.
     * Empêche l'extraction du texte par un malware Root avant chiffrement (Anti-TOCTOU).
     */
    fun promptHardwareConfirmation(
        promptText: String,
        extraData: ByteArray,
        executor: Executor,
        onSuccess: (ByteArray) -> Unit,
        onFailure: () -> Unit
    ) {
        if (!ConfirmationPrompt.isSupported(context)) {
            // Matériel non compatible avec l'affichage TEE
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
                // Signature matérielle validée directement par le TEE
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
}
