package com.example.aegis_app

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac

object HardwareKeystore {
    private const val TAG = "HardwareKeystore"
    private const val ALIAS = "aegis_strongbox_master_slot"
    private const val PROVIDER = "AndroidKeyStore"
    private val HARDWARE_SALT = "AEGIS_HMAC_STRONGBOX_SALT_V2".toByteArray(Charsets.UTF_8)

    @JvmStatic
    fun getHardwareSecret(isVaultEmpty: Boolean): ByteArray? {
        return try {
            val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

            if (isVaultEmpty && keyStore.containsAlias(ALIAS)) {
                keyStore.deleteEntry(ALIAS)
                Log.i(TAG, "Slot StrongBox orphelin purgé avec succès.")
            }

            if (!keyStore.containsAlias(ALIAS)) {
                val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, PROVIDER)
                val spec = KeyGenParameterSpec.Builder(
                    ALIAS,
                    KeyProperties.PURPOSE_SIGN
                )
                .setKeySize(256)
                .setIsStrongBoxBacked(true)
                .build()

                keyGenerator.init(spec)
                keyGenerator.generateKey()
                Log.i(TAG, "Nouvelle clé HMAC générée et scellée dans StrongBox TEE.")
            }

            val entry = keyStore.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry
            if (entry == null) {
                Log.e(TAG, "SecretKeyEntry introuvable dans KeyStore.")
                return null
            }

            val mac = Mac.getInstance("HmacSHA256").apply {
                init(entry.secretKey)
            }

            val derivedSecret = mac.doFinal(HARDWARE_SALT)
            Log.i(TAG, "Secret maître de 256 bits dérivé avec succès par StrongBox TEE.")
            derivedSecret
        } catch (e: Exception) {
            Log.e(TAG, "Échec critique lors de l'accès au StrongBox TEE", e)
            null
        }
    }
}