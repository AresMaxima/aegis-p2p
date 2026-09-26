package com.example.aegis_app

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.security.ConfirmationCallback
import android.security.ConfirmationPrompt
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import androidx.annotation.RequiresApi
import java.security.KeyStore
import java.util.concurrent.Executor
import javax.crypto.KeyGenerator

class ProtectedConfirmation(private val context: Context) {

    companion object {
        private const val TAG = "ProtectedConfirmation"
        private const val KEY_NAME = "aegis_master_root"
    }

    // Symboles Rust correspondants (à déclarer dans lib.rs) :
    //   Java_com_example_aegis_1app_ProtectedConfirmation_aegisPanicSilentBurn
    external fun aegisPanicSilentBurn()

    fun promptHardwareConfirmation(
        promptText: String,
        extraData: ByteArray,
        executor: Executor,
        onSuccess: (ByteArray) -> Unit,
        onFailure: () -> Unit
    ) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P ||
            !ConfirmationPrompt.isSupported(context)
        ) {
            onFailure()
            return
        }

        val prompt = ConfirmationPrompt.Builder(context)
            .setPromptText(promptText)
            .setExtraData(extraData)
            .build()

        prompt.presentPrompt(executor, object : ConfirmationCallback() {
            override fun onConfirmed(dataThatWasConfirmed: ByteArray) {
                super.onConfirmed(dataThatWasConfirmed)
                onSuccess(dataThatWasConfirmed)
            }
            override fun onCanceled() { super.onCanceled(); onFailure() }
            override fun onError(throwable: Throwable?) {
                super.onError(throwable)
                Log.e(TAG, "ConfirmationPrompt error", throwable)
                onFailure()
            }
        })
    }

    @RequiresApi(Build.VERSION_CODES.P)
    fun generateStrongBoxKey() {
        val kg = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
        )
        val builder = KeyGenParameterSpec.Builder(
            KEY_NAME,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationValidityDurationSeconds(0)
            .setIsStrongBoxBacked(true)

        try {
            kg.init(builder.build())
            kg.generateKey()
            Log.i(TAG, "Clé scellée dans le StrongBox.")
        } catch (e: StrongBoxUnavailableException) {
            Log.w(TAG, "StrongBox indisponible, fallback TEE classique.", e)
            val fallback = KeyGenParameterSpec.Builder(
                KEY_NAME,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(0)
                .build()
            kg.init(fallback)
            kg.generateKey()
        }
    }

    fun getSecurePromptIntent(): Intent? {
        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        return if (km.isDeviceSecure) {
            km.createConfirmDeviceCredentialIntent(
                "AEGIS Zero-Trust",
                "Saisissez votre code PIN d'accès matériel."
            )
        } else null
    }

    fun triggerCrisisBurn() {
        try {
            aegisPanicSilentBurn()
        } catch (t: Throwable) {
            Log.e(TAG, "aegisPanicSilentBurn indisponible", t)
        }
    }
}