package com.example.aegis_app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class HardwareKeystore(private val context: Context) {

    companion object {
        private const val KEY_ALIAS = "aegis_master_key_v2"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }

    fun generateStrongBoxKey(): Boolean {
        return try {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
            )

            val builder = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setIsStrongBoxBacked(true)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(1)
                .setInvalidatedByBiometricEnrollment(true)

            keyGenerator.init(builder.build())
            keyGenerator.generateKey()
            true
        } catch (e: StrongBoxUnavailableException) {
            false
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    fun decryptPayloadInHardware(encryptedData: ByteArray, iv: ByteArray): ByteArray? {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val secretKey = keyStore.getKey(KEY_ALIAS, null) as? SecretKey ?: return null

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

            cipher.doFinal(encryptedData)
        } catch (e: Exception) {
            null
        }
    }
}
