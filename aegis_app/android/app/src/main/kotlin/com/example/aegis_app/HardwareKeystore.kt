package com.example.aegis_app

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/**
 * Ancrage cryptographique matériel — v3.1 (fix 2026-09-22).
 *
 * v3.1 (2026-09-22) — FIX BUG SUPER-KEY LOCKED
 *   Sur SM-G985F (Exynos 990, Android 13), la clé StrongBox créée avec
 *   `setUnlockedDeviceRequired(true)` échoue à `Mac.init()` avec :
 *     "In unwrap_key: Required super decryption key is not in memory."
 *     ResponseCode(2) = LOCKED
 *   → La clé est créée OK, mais immédiatement inutilisable.
 *   Cause : incompatibilité StrongBox + HMAC + setUnlockedDeviceRequired
 *   sur ce chipset. La super-key keystore2 n'est jamais chargée pour
 *   cette combinaison, même device déverrouillé.
 *   → Fix : suppression de `setUnlockedDeviceRequired(true)`.
 *   → Bump alias v3_1 : les flags KeyStore sont immuables, il faut
 *     une nouvelle clé.
 *   → Sécurité : ce flag n'apporte rien, le PIN vault reste le facteur
 *     utilisateur. Sans le PIN, la clé StrongBox seule est inexploitable.
 *
 * v3.0 (2026-09-20) — Option 2
 *   Auth système retirée. HKDF(StrongBox_key || vault_PIN) côté Rust.
 *
 * Politique (Option 2) :
 *   • StrongBox génère une clé HMAC-256 scellée matériellement.
 *   • Cette clé est accessible sans auth système (AUTH=false).
 *   • Le facteur utilisateur est le VAULT PIN, combiné côté Rust via
 *     HKDF-SHA256(StrongBox_key || vault_PIN).
 *   • Deux facteurs réels : matériel (TEE) + connaissance (PIN).
 *
 * Compatibilité API 23 (minSdk) :
 *   • setIsStrongBoxBacked → API 28+ (guard P)
 */
object HardwareKeystore {

    private const val TAG = "HardwareKeystore"

    // v3.1 : alias bumpé pour forcer la régénération d'une clé propre.
    private const val ALIAS = "aegis_strongbox_master_slot_v3_1"

    // v3.1 : ancien alias — purgé au premier boot pour éviter les orphelins.
    private const val LEGACY_ALIAS_V3_0 = "aegis_strongbox_master_slot"

    private const val PROVIDER = "AndroidKeyStore"
    private val HARDWARE_SALT = "AEGIS_HMAC_STRONGBOX_SALT_V2".toByteArray(Charsets.UTF_8)

    /**
     * Vérifie si StrongBox est **réellement opérationnel** (P0-A.1e, D42-bis).
     *
     * Contrairement à un simple check `PackageManager.FEATURE_STRONGBOX_KEYSTORE`,
     * cette méthode tente **effectivement** de créer/utiliser une clé StrongBox.
     *
     * Précédent connu : SM-G985F (Exynos 990, Android 13) annonce StrongBox mais
     * `setUnlockedDeviceRequired(true)` le casse (bug v3.0 → v3.1, cf. notes en
     * tête de fichier). Un check passif n'aurait pas détecté ça.
     *
     * Comportement :
     *   • API < 28 → false (StrongBox indisponible sur cette version)
     *   • API ≥ 28 → tente `getHardwareSecret(requireStrongBox=true)` :
     *       - Success → true (StrongBox opérationnel, clé créée/chargée)
     *       - Failure → false (StrongBox absent/cassé, pas de fallback TEE)
     *
     * Coût : ~50-200 ms (création de clé si absente, sinon juste un Mac.init).
     *
     * Utilisé par P0-A.1e : Flutter appelle cette méthode au démarrage,
     * transmet le résultat à Rust via `aegis_tor_set_strongbox_available()`.
     * Si false → Tor refusé (fail-closed), mode dégradé local only (D62).
     */
    @JvmStatic
    fun isStrongBoxOperational(): Boolean {
        // 1. API guard : StrongBox requiert API 28+
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            Log.i(TAG, "isStrongBoxOperational: API ${Build.VERSION.SDK_INT} < 28 → false")
            return false
        }

        // 2. Active check : tenter de récupérer un secret StrongBox
        //    (crée la clé si absente, vérifie qu'elle est bien utilisable).
        //    requireStrongBox = true → pas de fallback TEE en cas d'échec.
        return when (val result = getHardwareSecret(isVaultEmpty = false, requireStrongBox = true)) {
            is HardwareSecretResult.Success -> {
                Log.i(TAG, "isStrongBoxOperational: OK (niveau=${result.level})")
                true
            }
            is HardwareSecretResult.Failure -> {
                Log.w(TAG, "isStrongBoxOperational: FAIL (${result.reason}, niveau=${result.lastKnownLevel})")
                false
            }
        }
    }

    enum class SecurityLevel {
        STRONGBOX,
        TEE,
        SOFTWARE,
    }

    sealed class HardwareSecretResult {
        data class Success(
            val secret: ByteArray,
            val level: SecurityLevel,
        ) : HardwareSecretResult()

        data class Failure(
            val reason: String,
            val lastKnownLevel: SecurityLevel? = null,
        ) : HardwareSecretResult()
    }

    @JvmStatic
    fun getHardwareSecret(
        isVaultEmpty: Boolean,
        requireStrongBox: Boolean = true,
    ): HardwareSecretResult {
        return try {
            val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }

            // v3.1 : purge inconditionnelle de l'alias v3.0 legacy (buggé).
            // L'ancienne clé a le flag setUnlockedDeviceRequired=true qui la
            // rend inutilisable. On s'en débarrasse à chaque démarrage.
            if (ks.containsAlias(LEGACY_ALIAS_V3_0)) {
                try {
                    ks.deleteEntry(LEGACY_ALIAS_V3_0)
                    Log.i(TAG, "Alias legacy v3.0 purgé (bug super-key LOCKED).")
                } catch (e: Exception) {
                    Log.w(TAG, "Purge alias legacy v3.0 échouée", e)
                }
            }

            if (isVaultEmpty && ks.containsAlias(ALIAS)) {
                ks.deleteEntry(ALIAS)
                Log.i(TAG, "Slot v3.1 orphelin purgé.")
            }

            if (!ks.containsAlias(ALIAS)) {
                generateKey(strongBox = true)
            }

            val entry = ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry
                ?: return HardwareSecretResult.Failure("SecretKeyEntry introuvable")

            val level = querySecurityLevel(entry.secretKey)
            if (requireStrongBox && level != SecurityLevel.STRONGBOX) {
                return HardwareSecretResult.Failure(
                    reason = "StrongBox requis mais niveau effectif = $level",
                    lastKnownLevel = level,
                )
            }

            val mac = Mac.getInstance("HmacSHA256").apply { init(entry.secretKey) }
            val bytes = mac.doFinal(HARDWARE_SALT)
            HardwareSecretResult.Success(bytes, level)

        } catch (e: StrongBoxUnavailableException) {
            Log.w(TAG, "StrongBox indisponible sur ce matériel.", e)
            if (requireStrongBox) {
                HardwareSecretResult.Failure("StrongBox requis mais indisponible sur ce matériel")
            } else {
                tryTeeFallback(isVaultEmpty)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Échec critique keystore", e)
            HardwareSecretResult.Failure("Exception keystore: ${e.javaClass.simpleName}")
        }
    }

    private fun tryTeeFallback(isVaultEmpty: Boolean): HardwareSecretResult {
        return try {
            val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
            if (isVaultEmpty && ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS)
            if (!ks.containsAlias(ALIAS)) generateKey(strongBox = false)

            val entry = ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry
                ?: return HardwareSecretResult.Failure("TEE fallback: entrée introuvable")

            val level = querySecurityLevel(entry.secretKey)
            val mac = Mac.getInstance("HmacSHA256").apply { init(entry.secretKey) }
            HardwareSecretResult.Success(mac.doFinal(HARDWARE_SALT), level)
        } catch (e: Exception) {
            HardwareSecretResult.Failure("TEE fallback échoué: ${e.javaClass.simpleName}")
        }
    }

    private fun querySecurityLevel(key: SecretKey): SecurityLevel {
        return try {
            // SecretKeyFactory (pas KeyFactory) est requis pour KeyInfo HMAC.
            val skf = SecretKeyFactory.getInstance(key.algorithm, PROVIDER)
            val info = skf.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> SecurityLevel.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> SecurityLevel.TEE
                else -> SecurityLevel.SOFTWARE
            }
        } catch (e: Exception) {
            Log.w(TAG, "Impossible d'interroger KeyInfo", e)
            SecurityLevel.SOFTWARE
        }
    }

    private fun generateKey(strongBox: Boolean) {
        val kg = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_HMAC_SHA256, PROVIDER
        )
        val builder = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setKeySize(256)
            .setDigests(KeyProperties.DIGEST_SHA256)
            // -------------------------------------------------------------
            // v3.1 (2026-09-22) : setUnlockedDeviceRequired(true) RETIRÉ.
            //
            // Raison : sur SM-G985F (Exynos 990, Android 13), la combinaison
            // StrongBox + HMAC + setUnlockedDeviceRequired provoque l'erreur :
            //   "In unwrap_key: Required super decryption key is not in memory"
            //   ResponseCode(2) = LOCKED
            // → la clé est créée mais immédiatement inutilisable.
            //
            // Le flag n'apportait AUCUN gain de sécurité dans notre modèle :
            // le PIN vault fournit le facteur utilisateur. Sans PIN, la clé
            // StrongBox seule est inexploitable. On le retire.
            // -------------------------------------------------------------

        // API 28+ : StrongBox (le constructeur renvoie StrongBoxUnavailableException
        // si l'enclave matérielle n'existe pas — catchée par getHardwareSecret()).
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }

        kg.init(builder.build())
        kg.generateKey()
        Log.i(TAG, "Clé HMAC générée (strongBox=$strongBox, API=${Build.VERSION.SDK_INT}, auth=none, no-unlock-required, PIN-binder)")
    }
}