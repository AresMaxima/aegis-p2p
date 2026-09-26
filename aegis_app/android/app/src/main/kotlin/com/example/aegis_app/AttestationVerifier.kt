package com.example.aegis_app

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/**
 * Android Key Attestation — Niveau 3 (CdCM v2.2-RC3).
 *
 * ─────────────────────────────────────────────────────────────────────
 * PRINCIPE :
 *   1. Génère une clé EC P-256 dans StrongBox/TEE avec attestation.
 *   2. Le challenge d'attestation = SHA-256 de la signature APK.
 *   3. La chaîne de certificats X.509 retournée est signée par la
 *      racine matérielle (Samsung Knox / Google Titan).
 *   4. Rust vérifie :
 *      • la chaîne cryptographique remonte à Samsung/Google,
 *      • le challenge == hash de la signature APK,
 *      • verifiedBootState == GREEN (bootloader verrouillé),
 *      • deviceLocked == true,
 *      • verifiedBootHash non-vide (système intègre).
 *
 *   Si l'une des vérifications échoue → PanicPurge (exit 137).
 * ─────────────────────────────────────────────────────────────────────
 */
object AttestationVerifier {
    private const val TAG = "AegisAttestation"
    private const val ATTESTATION_ALIAS = "aegis_attestation_key_v1"
    private const val PROVIDER = "AndroidKeyStore"

    /**
     * Résultat d'attestation prêt à être envoyé à Rust.
     */
    data class AttestationData(
        /** Concatenation DER : cert[0]_DER || cert[1]_DER || ... */
        val chain: ByteArray,
        /** SHA-256 de la signature APK (32 octets). */
        val challenge: ByteArray,
    )

    /**
     * Récupère (ou génère) la chaîne d'attestation matérielle.
     * Retourne null si l'attestation n'est pas supportée ou échoue.
     */
    @JvmStatic
    fun getAttestationData(context: Context): AttestationData? {
        return try {
            // 1) Calculer le challenge = SHA-256 de la signature APK
            val challenge = computeApkSignatureHash(context)
                ?: run {
                    Log.e(TAG, "Impossible de calculer le hash de signature APK")
                    return null
                }

            // 2) Charger le KeyStore Android
            val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }

            // 3) Générer la clé d'attestation si elle n'existe pas
            if (!ks.containsAlias(ATTESTATION_ALIAS)) {
                generateAttestationKey(challenge)
            }

            // 4) Récupérer l'entrée (doit être un PrivateKeyEntry)
            val entry = ks.getEntry(ATTESTATION_ALIAS, null)
                    as? KeyStore.PrivateKeyEntry
                ?: run {
                    Log.e(TAG, "PrivateKeyEntry introuvable pour $ATTESTATION_ALIAS")
                    return null
                }

            // 5) Récupérer la chaîne de certificats
            val certs = entry.certificateChain
            if (certs.isEmpty()) {
                Log.e(TAG, "Chaîne de certificats vide")
                return null
            }

            // 6) Concatener les certificats en DER
            val out = ByteArrayOutputStream()
            var x509Count = 0
            for (cert in certs) {
                if (cert is X509Certificate) {
                    out.write(cert.encoded)
                    x509Count++
                }
            }
            if (x509Count == 0) {
                Log.e(TAG, "Aucun certificat X.509 dans la chaîne")
                return null
            }

            Log.i(
                TAG,
                "Attestation récupérée : $x509Count certs, ${out.size()} bytes DER, " +
                "challenge=${challenge.size} bytes"
            )

            AttestationData(
                chain = out.toByteArray(),
                challenge = challenge,
            )
        } catch (e: Exception) {
            Log.e(TAG, "getAttestationData a échoué", e)
            null
        }
    }

    /**
     * Calcule SHA-256 de la signature APK.
     *
     * Utilise `GET_SIGNING_CERTIFICATES` (API 28+) ou `GET_SIGNATURES` (legacy).
     * Le certificat APK est encodé en DER, puis hashé en SHA-256.
     */
    private fun computeApkSignatureHash(context: Context): ByteArray? {
        return try {
            val pm = context.packageManager
            val packageName = context.packageName

            val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
            }

            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                info.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                info.signatures
            } ?: run {
                Log.e(TAG, "signingInfo null")
                return null
            }

            if (signatures.isEmpty()) {
                Log.e(TAG, "Aucune signature APK trouvée")
                return null
            }

            // Le certificat X.509 de signature, en DER
            val certBytes = signatures[0].toByteArray()
            val hash = MessageDigest.getInstance("SHA-256").digest(certBytes)

            Log.i(TAG, "APK signature hash: ${hash.joinToString("") { "%02x".format(it) }}")
            hash
        } catch (e: Exception) {
            Log.e(TAG, "computeApkSignatureHash a échoué", e)
            null
        }
    }

    /**
     * Génère une clé EC P-256 avec attestation et challenge.
     *
     * Tente StrongBox (API 28+) en priorité, avec fallback TEE.
     */
    private fun generateAttestationKey(challenge: ByteArray) {
        val kg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            PROVIDER,
        )

        val builder = KeyGenParameterSpec.Builder(
            ATTESTATION_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .setUserAuthenticationRequired(false)

        // Tentative StrongBox (API 28+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                builder.setIsStrongBoxBacked(true)
                kg.initialize(builder.build())
                kg.generateKeyPair()
                Log.i(TAG, "Clé d'attestation générée (StrongBox)")
                return
            } catch (e: StrongBoxUnavailableException) {
                Log.w(TAG, "StrongBox indisponible, fallback TEE", e)
            } catch (e: Exception) {
                Log.w(TAG, "StrongBox a échoué (code=${e.javaClass.simpleName}), fallback TEE", e)
            }
        }

        // Fallback TEE
        builder.setIsStrongBoxBacked(false)
        kg.initialize(builder.build())
        kg.generateKeyPair()
        Log.i(TAG, "Clé d'attestation générée (TEE)")
    }
}