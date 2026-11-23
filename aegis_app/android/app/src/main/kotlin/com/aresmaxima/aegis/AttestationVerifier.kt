package com.aresmaxima.aegis

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
 * Android Key Attestation â€” Niveau 3 (CdCM v2.2-RC3).
 *
 * â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 * PRINCIPE :
 *   1. GÃ©nÃ¨re une clÃ© EC P-256 dans StrongBox/TEE avec attestation.
 *   2. Le challenge d'attestation = SHA-256 de la signature APK.
 *   3. La chaÃ®ne de certificats X.509 retournÃ©e est signÃ©e par la
 *      racine matÃ©rielle (Samsung Knox / Google Titan).
 *   4. Rust vÃ©rifie :
 *      â€¢ la chaÃ®ne cryptographique remonte Ã  Samsung/Google,
 *      â€¢ le challenge == hash de la signature APK,
 *      â€¢ verifiedBootState == GREEN (bootloader verrouillÃ©),
 *      â€¢ deviceLocked == true,
 *      â€¢ verifiedBootHash non-vide (systÃ¨me intÃ¨gre).
 *
 *   Si l'une des vÃ©rifications Ã©choue â†’ PanicPurge (exit 137).
 * â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 */
object AttestationVerifier {
    private const val TAG = "AegisAttestation"
    private const val ATTESTATION_ALIAS = "aegis_attestation_key_v1"
    private const val PROVIDER = "AndroidKeyStore"

    /**
     * RÃ©sultat d'attestation prÃªt Ã  Ãªtre envoyÃ© Ã  Rust.
     */
    data class AttestationData(
        /** Concatenation DER : cert[0]_DER || cert[1]_DER || ... */
        val chain: ByteArray,
        /** SHA-256 de la signature APK (32 octets). */
        val challenge: ByteArray,
    )

    /**
     * RÃ©cupÃ¨re (ou gÃ©nÃ¨re) la chaÃ®ne d'attestation matÃ©rielle.
     * Retourne null si l'attestation n'est pas supportÃ©e ou Ã©choue.
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

            // 3) D63 FIX : Toujours rÃ©gÃ©nÃ©rer la clÃ© d'attestation.
            // Le challenge change Ã  chaque signature d'APK (nouvelle clÃ© de release).
            // Une clÃ© d'attestation liÃ©e Ã  un ancien challenge produit un certificat
            // avec un ChallengeMismatch, ce qui dÃ©clenche panic_purge() cÃ´tÃ© Rust.
            if (ks.containsAlias(ATTESTATION_ALIAS)) {
                try {
                    ks.deleteEntry(ATTESTATION_ALIAS)
                    Log.i(TAG, "D63 FIX : ancienne clÃ© d'attestation supprimÃ©e")
                } catch (e: Exception) {
                    Log.w(TAG, "Impossible de supprimer l'ancienne clÃ© d'attestation", e)
                }
            }

            // 4) GÃ©nÃ©rer la clÃ© d'attestation avec le nouveau challenge
            generateAttestationKey(challenge)

            // 5) RÃ©cupÃ©rer l'entrÃ©e (doit Ãªtre un PrivateKeyEntry)
            val entry = ks.getEntry(ATTESTATION_ALIAS, null)
                    as? KeyStore.PrivateKeyEntry
                ?: run {
                    Log.e(TAG, "PrivateKeyEntry introuvable pour $ATTESTATION_ALIAS")
                    return null
                }

            // 6) RÃ©cupÃ©rer la chaÃ®ne de certificats
            val certs = entry.certificateChain
            if (certs.isEmpty()) {
                Log.e(TAG, "ChaÃ®ne de certificats vide")
                return null
            }

            // 7) Concatener les certificats en DER
            val out = ByteArrayOutputStream()
            var x509Count = 0
            for (cert in certs) {
                if (cert is X509Certificate) {
                    out.write(cert.encoded)
                    x509Count++
                }
            }
            if (x509Count == 0) {
                Log.e(TAG, "Aucun certificat X.509 dans la chaÃ®ne")
                return null
            }

            Log.i(
                TAG,
                "Attestation rÃ©cupÃ©rÃ©e : $x509Count certs, ${out.size()} bytes DER, " +
                "challenge=${challenge.size} bytes"
            )

            AttestationData(
                chain = out.toByteArray(),
                challenge = challenge,
            )
        } catch (e: Exception) {
            Log.e(TAG, "getAttestationData a Ã©chouÃ©", e)
            null
        }
    }

    /**
     * Calcule SHA-256 de la signature APK.
     *
     * Utilise `GET_SIGNING_CERTIFICATES` (API 28+) ou `GET_SIGNATURES` (legacy).
     * Le certificat APK est encodÃ© en DER, puis hashÃ© en SHA-256.
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
                Log.e(TAG, "Aucune signature APK trouvÃ©e")
                return null
            }

            // Le certificat X.509 de signature, en DER
            val certBytes = signatures[0].toByteArray()
            val hash = MessageDigest.getInstance("SHA-256").digest(certBytes)

            Log.i(TAG, "APK signature hash: ${hash.joinToString("") { "%02x".format(it) }}")
            hash
        } catch (e: Exception) {
            Log.e(TAG, "computeApkSignatureHash a Ã©chouÃ©", e)
            null
        }
    }

    /**
     * GÃ©nÃ¨re une clÃ© EC P-256 avec attestation et challenge.
     *
     * Tente StrongBox (API 28+) en prioritÃ©, avec fallback TEE.
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
                Log.i(TAG, "ClÃ© d'attestation gÃ©nÃ©rÃ©e (StrongBox)")
                return
            } catch (e: StrongBoxUnavailableException) {
                Log.w(TAG, "StrongBox indisponible, fallback TEE", e)
            } catch (e: Exception) {
                Log.w(TAG, "StrongBox a Ã©chouÃ© (code=${e.javaClass.simpleName}), fallback TEE", e)
            }
        }

        // Fallback TEE
        builder.setIsStrongBoxBacked(false)
        kg.initialize(builder.build())
        kg.generateKeyPair()
        Log.i(TAG, "ClÃ© d'attestation gÃ©nÃ©rÃ©e (TEE)")
    }

    @JvmStatic
    fun getPeerBoundAttestationChain(peerPk: ByteArray, nonce: ByteArray): ByteArray? {
        if (peerPk.size != 32 || nonce.size != 32) return null
        return try {
            val md = MessageDigest.getInstance("SHA-256")
            md.update("AEGIS-P2P-ATTEST-v3.6:".toByteArray())
            md.update(peerPk); md.update(nonce)
            generateAttestationKey(md.digest())
            val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
            val entry = ks.getEntry(ATTESTATION_ALIAS, null) as? KeyStore.PrivateKeyEntry ?: return null
            val out = ByteArrayOutputStream()
            for (c in entry.certificateChain) { if (c is X509Certificate) out.write(c.encoded) }
            if (out.size() > 0) out.toByteArray() else null
        } catch (e: Exception) { Log.e(TAG, "PeerAttest err", e); null }
    }
}
