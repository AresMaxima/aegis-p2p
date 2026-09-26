// aegis_app/android/app/src/androidTest/kotlin/com/example/aegis_app/HardwareKeystoreTest.kt

package com.example.aegis_app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class HardwareKeystoreTest {

    private val ctx get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun setup() {
        // Purge l'alias avant chaque test pour repartir propre
        val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (ks.containsAlias("aegis_strongbox_master_slot")) {
            ks.deleteEntry("aegis_strongbox_master_slot")
        }
    }

    @Test
    fun testGetHardwareSecretReturnsStrongBoxOnCompatibleDevice() {
        val result = HardwareKeystore.getHardwareSecret(
            isVaultEmpty = true,
            requireStrongBox = true,
        )
        assertTrue("Doit retourner un Success sur device compatible",
            result is HardwareKeystore.HardwareSecretResult.Success)
        val success = result as HardwareKeystore.HardwareSecretResult.Success
        assertEquals("Niveau attendu STRONGBOX",
            HardwareKeystore.SecurityLevel.STRONGBOX, success.level)
        assertEquals("Secret 32 octets (HMAC-SHA256)", 32, success.secret.size)
    }

    @Test
    fun testFailsWhenStrongBoxRequiredButUnavailable() {
        // Sur device sans StrongBox, requireStrongBox=true doit échouer proprement
        val result = HardwareKeystore.getHardwareSecret(
            isVaultEmpty = true,
            requireStrongBox = true,
        )
        when (result) {
            is HardwareKeystore.HardwareSecretResult.Failure -> {
                // OK : device sans StrongBox → échec explicite
                assertTrue(result.reason.contains("StrongBox"))
            }
            is HardwareKeystore.HardwareSecretResult.Success -> {
                // OK : device a du StrongBox → on a STRONGBOX
                assertEquals(HardwareKeystore.SecurityLevel.STRONGBOX, result.level)
            }
        }
    }

    @Test
    fun testSecretIsDeterministicForSameKey() {
        val r1 = HardwareKeystore.getHardwareSecret(isVaultEmpty = true, requireStrongBox = false)
        val r2 = HardwareKeystore.getHardwareSecret(isVaultEmpty = false, requireStrongBox = false)
        val s1 = (r1 as HardwareKeystore.HardwareSecretResult.Success).secret
        val s2 = (r2 as HardwareKeystore.HardwareSecretResult.Success).secret
        assertArrayEquals("HMAC-SHA256 déterministe sur la même clé", s1, s2)
    }
}