package com.aresmaxima.aegis

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.nfc.NfcAdapter
import android.nfc.tech.IsoDep
import android.os.Debug
import java.security.MessageDigest
import android.util.Log
import android.view.Surface
import androidx.annotation.NonNull
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleOwner
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.nio.ByteBuffer
import java.util.concurrent.Executors

class MainActivity : FlutterActivity() {

    companion object {
        private const val TAG = "AEGIS_MAIN"
        private const val KEYSTORE_CHANNEL = "com.aegis/keystore"
        private const val TEE_UI_CHANNEL   = "com.aegis.p2p/tee_ui"
        private const val CAMERA_CHANNEL   = "com.aegis.p2p/camera"
        private const val CAMERA_PERMISSION_CODE = 1002
        private const val WIFI_DIRECT_CHANNEL = "com.aegis/wifi_direct"
        private const val WIFI_DIRECT_EVENTS_CHANNEL = "com.aegis/wifi_direct_events"

        init {
            System.loadLibrary("aegis_core")
        }

        // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // RÃ©fÃ©rence vers le PreviewView CameraX (aperÃ§u live).
        // RenseignÃ©e par CameraPreviewView.init(), utilisÃ©e par
        // startCameraInternal() pour lier le use case Preview.
        // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        @Volatile
        private var currentPreviewView: PreviewView? = null

        fun attachPreviewView(view: PreviewView) {
            currentPreviewView = view
            Log.i(TAG, "attachPreviewView OK")
        }

        fun detachPreviewView(view: PreviewView) {
            if (currentPreviewView === view) {
                currentPreviewView = null
                Log.i(TAG, "detachPreviewView OK")
            }
        }

        fun getPreviewView(): PreviewView? = currentPreviewView
    }

    // =====================================================================
    // DÃ©clarations JNI â€” Rust (lib.rs)
    // =====================================================================

    external fun aegisRegisterMainActivity(activity: MainActivity)
    external fun aegis_render_to_surface(surface: Surface): Int
    external fun aegis_release_surface(): Int
    external fun aegis_ingest_camera_frame_direct(
        y: ByteBuffer, yLen: Int,
        u: ByteBuffer, uLen: Int,
        v: ByteBuffer, vLen: Int,
        width: Int, height: Int
    ): Int
    external fun aegis_control_media_player(cmd: String, param: Double): Int

    // ---------------------------------------------------------------------
    // Option 2 (audit 2026-09-20) : dÃ©rivation de la master_key via HKDF-SHA256.
    // Combine la clÃ© StrongBox (ROOT_KEY cÃ´tÃ© Rust) et le vault PIN.
    // 0 = OK, -1 = JNI, -2 = PIN vide, -3 = ROOT_KEY manquante, -4 = autre.
    // ---------------------------------------------------------------------
    external fun aegis_derive_and_set_master_key(pin: String): Int

    // ---------------------------------------------------------------------
    // Niveau 3 â€” Android Key Attestation.
    // ReÃ§oit la chaÃ®ne DER concatÃ©nÃ©e + le challenge (SHA-256 APK).
    // Retourne 0 si OK, un code nÃ©gatif sinon (Rust purge si compromis).
    // ---------------------------------------------------------------------
    external fun aegis_verify_attestation_chain(
        chain: ByteArray,
        challenge: ByteArray,
    ): Int

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // P0-A.3c.2 (2026-10-12) â€” BLE Mesh JNI pipes.
    // AppelÃ©s depuis BleMeshBridge via la classe MainActivity.
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    external fun aegis_ble_mesh_set_pipes(inFd: Int, outFd: Int): Int
    external fun aegis_ble_mesh_shutdown(): Int

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // P0-A.3d.3b (2026-10-14) â€” BLE Mesh reader thread.
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    external fun aegis_ble_mesh_reader_start(inFd: Int, outFd: Int): Int
    external fun aegis_ble_mesh_reader_stop(): Int

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // P0-A.3e.2b.1 (2026-10-16) â€” BLE handshake ed25519.
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    external fun aegis_ble_handshake_start_initiator(fp: ByteArray): Int
    external fun aegis_ble_handshake_start_responder(fp: ByteArray): Int
    external fun aegis_ble_handshake_is_complete(): Int
    external fun aegis_ble_handshake_reset(): Int

    /**
     * Wrapper Kotlin : rÃ©cupÃ¨re l'attestation matÃ©rielle et la fait
     * vÃ©rifier par Rust.
     *
     * 0  = attestation OK
     * -1 = pas de support d'attestation (device legacy)
     * -2 = Ã©chec de rÃ©cupÃ©ration de la chaÃ®ne
     * -3..-N = chaÃ®ne compromise (Rust a dÃ©jÃ  purgÃ©)
     */
    fun aegisVerifyDeviceAttestation(): Int {
        val data = AttestationVerifier.getAttestationData(this)
            ?: return -2

        return try {
            aegis_verify_attestation_chain(data.chain, data.challenge)
        } catch (t: Throwable) {
            Log.e(TAG, "aegis_verify_attestation_chain a Ã©chouÃ©", t)
            -1
        }
    }

    /**
     * N3 (audit 2026-09-20) : dÃ©tecte si l'APK est signÃ©e avec la clÃ©
     * debug standard Android (`CN=Android Debug, O=Android, C=US`).
     */
    private fun isSignedWithDebugKey(): Boolean {
        return try {
            val flags = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                PackageManager.GET_SIGNING_CERTIFICATES
            } else {
                @Suppress("DEPRECATION")
                PackageManager.GET_SIGNATURES
            }
            val info = packageManager.getPackageInfo(packageName, flags)

            @Suppress("DEPRECATION")
            val signers = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                info.signingInfo?.apkContentsSigners
            } else {
                info.signatures
            } ?: return false

            for (signer in signers) {
                val cert = java.security.cert.CertificateFactory
                    .getInstance("X.509")
                    .generateCertificate(signer.toByteArray().inputStream())
                        as java.security.cert.X509Certificate
                val dn = cert.subjectX500Principal.name
                if (dn.contains("CN=Android Debug", ignoreCase = true)) {
                    return true
                }
            }
            false
        } catch (e: Exception) {
            Log.e(TAG, "Impossible de vÃ©rifier la signature de l'APK", e)
            false
        }
    }

    // =====================================================================
    // P1 / P2 â€” SÃ©curitÃ© Forensique & Anti-Root
    // =====================================================================

    /**
     * P2 (P-5) : DÃ©tecte si l'environnement est compromis (Root, Frida, Debugger).
     */
    private fun isDeviceCompromised(): Boolean {
        // 1. DÃ©tection de Debugger attachÃ©
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            Log.e(TAG, "P2: Debugger dÃ©tectÃ© !")
            return true
        }

        // 2. DÃ©tection de Root (fichiers / binaires su)
        val rootPaths = arrayOf(
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su",
            "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su"
        )
        for (path in rootPaths) {
            if (File(path).exists()) {
                Log.e(TAG, "P2: Root dÃ©tectÃ© via $path !")
                return true
            }
        }

        // 3. DÃ©tection de Frida (ports ouverts ou processus)
        try {
            val process = Runtime.getRuntime().exec("ps -A")
            val reader = process.inputStream.bufferedReader()
            val output = reader.readText()
            if (output.contains("frida-server") || output.contains("frida-helper")) {
                Log.e(TAG, "P2: Frida dÃ©tectÃ© !")
                return true
            }
        } catch (_: Throwable) {}

        return false
    }

    /**
     * P1 (fstrim) : Force l'OS Ã  Ã©craser les blocs libres.
     * Alloue un fichier massif (100 Mo) pour Ã©craser les anciennes donnÃ©es, puis le supprime.
     * NOTE : ExÃ©cutÃ© sur un thread sÃ©parÃ© pour Ã©viter un ANR si appelÃ© dans onDestroy.
     */
    fun aegisForceFstrim() {
        Thread {
            try {
                val dummyFile = File(filesDir, "aegis_fstrim_dummy.dat")
                val fos = java.io.FileOutputStream(dummyFile)
                val buffer = ByteArray(1024 * 1024) // 1 Mo
                java.util.Random().nextBytes(buffer)
                for (i in 0 until 100) {
                    fos.write(buffer)
                }
                fos.flush()
                fos.close()
                dummyFile.delete()
                Log.i(TAG, "P1: fstrim trigger OK (100 MB allocated & deleted)")
            } catch (e: Throwable) {
                Log.e(TAG, "P1: fstrim trigger failed", e)
            }
        }.start()
    }

    // =====================================================================
    // Ã‰tat interne
    // =====================================================================

    private lateinit var protectedConfirmation: ProtectedConfirmation
    private var pendingResult: MethodChannel.Result? = null
    private val cameraExecutor = Executors.newSingleThreadExecutor()
    private var cameraProvider: ProcessCameraProvider? = null

    private var bleMeshBridge: BleMeshBridge? = null

    private var yPool: ByteBuffer? = null
    private var uPool: ByteBuffer? = null
    private var vPool: ByteBuffer? = null

    // =====================================================================
    // Cycle de vie
    // =====================================================================

    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)

        // P2 (P-5) : Fail-closed si l'environnement est compromis.
        if (isDeviceCompromised()) {
            Log.e(TAG, "P2: Environnement compromis â€” PanicPurge (Process Kill).")
            // On tue le processus immÃ©diatement.
            android.os.Process.killProcess(android.os.Process.myPid())
            System.exit(0)
        }

        // CRUCIAL : enregistrer l'instance AVANT tout appel de aegis_capture_ndk_camera.
        try {
            aegisRegisterMainActivity(this)
        } catch (t: Throwable) {
            Log.e(TAG, "aegisRegisterMainActivity a Ã©chouÃ©", t)
        }

        // P0-A.2a (2026-10-07) : initialisation du bridge Wi-Fi Direct.
        try {
            val wifiOk = WifiDirectBridge.initialize(this)
            Log.i(TAG, "WifiDirectBridge.initialize = $wifiOk")
        } catch (t: Throwable) {
            Log.e(TAG, "WifiDirectBridge.initialize a Ã©chouÃ©", t)
        }

        // ============================================================
        // N3 (audit 2026-09-20) : politique d'attestation automatique.
        // ============================================================
        val isDebugSigned = isSignedWithDebugKey()
        if (isDebugSigned) {
            Log.w(TAG, "APK signÃ©e avec clÃ© DEBUG â€” ATTESTATION SKIPPED (mode dev)")
        } else {
            Log.i(TAG, "APK release-signÃ©e â€” ATTESTATION ACTIVE")
            try {
                val attestationResult = aegisVerifyDeviceAttestation()
                Log.i(TAG, "Attestation result: $attestationResult")
                if (attestationResult < 0) {
                    Log.e(TAG, "Attestation compromise (code=$attestationResult)")
                }
            } catch (t: Throwable) {
                Log.e(TAG, "Attestation verification a Ã©chouÃ©", t)
            }
        }
    }

    override fun onDestroy() {
        // P1 : Force l'OS Ã  Ã©craser les blocs libres aprÃ¨s le dÃ©part de l'app.
        try { aegisForceFstrim() } catch (_: Throwable) {}

        try { cameraProvider?.unbindAll() } catch (_: Throwable) {}
        try { aegis_release_surface() } catch (_: Throwable) {}
        // P0-A.3a : arrÃªt du bridge BLE Mesh
        try { bleMeshBridge?.destroy() } catch (_: Throwable) {}
        bleMeshBridge = null
        try { WifiDirectBridge.shutdown() } catch (_: Throwable) {}
        cameraExecutor.shutdown()
        super.onDestroy()
    }

    // =====================================================================
    // MÃ©thode appelÃ©e depuis Rust via JNI (aegis_capture_ndk_camera)
    // =====================================================================

    fun aegisStartHardwareCapture(): Int {
        return try {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
                != PackageManager.PERMISSION_GRANTED
            ) {
                runOnUiThread {
                    ActivityCompat.requestPermissions(
                        this,
                        arrayOf(Manifest.permission.CAMERA),
                        CAMERA_PERMISSION_CODE
                    )
                }
                -10
            } else {
                runOnUiThread { startCameraInternal() }
                0
            }
        } catch (t: Throwable) {
            Log.e(TAG, "aegisStartHardwareCapture a Ã©chouÃ©", t)
            -1
        }
    }

    fun aegisStopHardwareCapture(): Int {
        return try {
            cameraProvider?.unbindAll()
            Log.i(TAG, "CameraX: unbindAll (stop hardware capture)")
            0
        } catch (t: Throwable) {
            Log.e(TAG, "aegisStopHardwareCapture a Ã©chouÃ©", t)
            -1
        }
    }

    // =====================================================================
    // Flutter Engine
    // =====================================================================

    override fun configureFlutterEngine(@NonNull flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        protectedConfirmation = ProtectedConfirmation(this)

        // P0-A.3a (2026-10-11) : bridge BLE Mesh
        bleMeshBridge = BleMeshBridge(this, flutterEngine.dartExecutor.binaryMessenger)

        // PlatformView : surface VRAM (BlindView).
        flutterEngine.platformViewsController.registry.registerViewFactory(
            "com.aegis.p2p/blind_surface",
            BlindViewFactory()
        )

        // PlatformView : aperÃ§u camÃ©ra live (CameraPreviewView).
        flutterEngine.platformViewsController.registry.registerViewFactory(
            "com.aegis.p2p/camera_preview",
            CameraPreviewViewFactory()
        )

        // --- Canal keystore ---
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, KEYSTORE_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "getHardwareSecret" -> {
                        val isVaultEmpty = call.argument<Boolean>("isVaultEmpty") ?: false
                        val requireStrongBox = call.argument<Boolean>("requireStrongBox") ?: true

                        when (val hw = HardwareKeystore.getHardwareSecret(isVaultEmpty, requireStrongBox)) {
                            is HardwareKeystore.HardwareSecretResult.Success -> {
                                if (hw.secret.size == 32) {
                                    Log.i(TAG, "Hardware secret OK (niveau=${hw.level})")
                                    result.success(hw.secret)
                                } else {
                                    result.error("TEE_ERROR", "Taille secrÃ¨te invalide: ${hw.secret.size} (attendu 32)", null)
                                }
                            }
                            is HardwareKeystore.HardwareSecretResult.Failure -> {
                                Log.e(TAG, "Hardware secret indisponible: ${hw.reason} (niveau=${hw.lastKnownLevel})")
                                result.error("TEE_ERROR", hw.reason, null)
                            }
                        }
                    }

                    "deriveMasterKey" -> {
                        val pin = call.argument<String>("pin")
                        if (pin.isNullOrEmpty()) {
                            result.error("MASTER_ERROR", "PIN vide", null)
                            return@setMethodCallHandler
                        }
                        val rc = aegis_derive_and_set_master_key(pin)
                        if (rc == 0) {
                            Log.i(TAG, "Master key dÃ©rivÃ©e (HKDF-SHA256) â€” PIN combinÃ© StrongBox")
                            result.success(true)
                        } else {
                            Log.e(TAG, "deriveMasterKey a Ã©chouÃ©: rc=$rc")
                            result.error("MASTER_ERROR", "rc=$rc", null)
                        }
                    }

                    "isStrongBoxOperational" -> {
                        val available = HardwareKeystore.isStrongBoxOperational()
                        Log.i(TAG, "isStrongBoxOperational = $available")
                        result.success(available)
                    }

                    "generateLicenseKey" -> {
                        val success = HardwareKeystore.generateLicenseKey()
                        Log.i(TAG, "generateLicenseKey = $success")
                        result.success(success)
                    }

                    "getLicensePublicKey" -> {
                        val pubkey = HardwareKeystore.getLicensePublicKeyHex()
                        Log.i(TAG, "getLicensePublicKey = ${pubkey?.take(16)}...")
                        result.success(pubkey)
                    }

                                        "generatePeerAttestationChain" -> {
                        val pk = call.argument<ByteArray>("peerEd25519Pk")
                        val nc = call.argument<ByteArray>("sessionNonce")
                        if (pk == null || nc == null) { result.error("ARG", "null", null); return@setMethodCallHandler }
                        Thread { val d = AttestationVerifier.getPeerBoundAttestationChain(pk, nc); runOnUiThread { if (d != null) result.success(d) else result.error("ATT", "fail", null) } }.start()
                    }
                    "enrollNfcHardwareToken" -> {
                        val ch = call.argument<ByteArray>("challenge") ?: ByteArray(32)
                        val nfc = NfcAdapter.getDefaultAdapter(this)
                        if (nfc == null || !nfc.isEnabled) { result.error("NFC", "off", null); return@setMethodCallHandler }
                        val ok = java.util.concurrent.atomic.AtomicBoolean(false)
                        nfc.enableReaderMode(this, { tag ->
                            val md = MessageDigest.getInstance("SHA-256")
                            md.update("AEGIS-C94:".toByteArray()); md.update(tag.id); md.update(ch)
                            try { IsoDep.get(tag)?.use { it.connect(); md.update(it.transceive(byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, 0x08, 0xA0.toByte(), 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01))) } } catch (_: Exception) {}
                            val out = md.digest()
                            runOnUiThread { try { nfc.disableReaderMode(this) } catch (_: Exception) {}; if (ok.compareAndSet(false, true)) result.success(out) }
                        }, NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null)
                    }
                    else -> result.notImplemented()
                }
            }

        // --- Canal TEE-UI ---
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, TEE_UI_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "invokeHardwarePrompt" -> {
                        val intent = protectedConfirmation.getSecurePromptIntent()
                        if (intent != null) {
                            pendingResult = result
                            startActivityForResult(intent, 1001)
                        } else {
                            result.error("UNSECURE_DEVICE", "Aucun PIN systÃ¨me.", null)
                        }
                    }
                    "triggerPanic" -> {
                        protectedConfirmation.triggerCrisisBurn()
                        result.success(true)
                    }
                    else -> result.notImplemented()
                }
            }

        // --- Canal Wi-Fi Direct (P0-A.2a) ---
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, WIFI_DIRECT_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "isSupported" -> result.success(WifiDirectBridge.isSupported(this))
                    "getEphemeralName" -> result.success(WifiDirectBridge.getEphemeralName())
                    "getEphemeralPort" -> result.success(WifiDirectBridge.getEphemeralPort())
                    "getState" -> result.success(WifiDirectBridge.getState())
                    "startDiscovery" -> {
                        val code = WifiDirectBridge.startDiscovery(null)
                        if (code == 0) result.success(true) else result.error("DISCOVERY_ERROR", "code=$code", null)
                    }
                    "stopDiscovery" -> {
                        val code = WifiDirectBridge.stopDiscovery()
                        if (code == 0) result.success(true) else result.error("DISCOVERY_ERROR", "code=$code", null)
                    }
                    "connectToPeer" -> {
                        val name = call.argument<String>("deviceName") ?: ""
                        val port = call.argument<Int>("peerPort") ?: 0
                        val code = WifiDirectBridge.connectToPeer(name, port)
                        if (code == 0) result.success(true) else result.error("CONNECT_ERROR", "code=$code", null)
                    }
                    "disconnect" -> {
                        val code = WifiDirectBridge.disconnect()
                        if (code == 0) result.success(true) else result.error("DISCONNECT_ERROR", "code=$code", null)
                    }
                    "closeFd" -> {
                        val rc = WifiDirectBridge.disconnect()
                        if (rc == 0) result.success(true) else result.error("CLOSE_ERROR", "code=$rc", null)
                    }
                    else -> result.notImplemented()
                }
            }

        // --- EventChannel Wi-Fi Direct (P0-A.2b.2) ---
        EventChannel(flutterEngine.dartExecutor.binaryMessenger, WIFI_DIRECT_EVENTS_CHANNEL)
            .setStreamHandler(object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                    WifiDirectBridge.setEventSink(events)
                }
                override fun onCancel(arguments: Any?) {
                    WifiDirectBridge.setEventSink(null)
                }
            })

        // --- Canal camÃ©ra native ---
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CAMERA_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "startNativeCamera" -> {
                        val code = aegisStartHardwareCapture()
                        if (code == 0) result.success(0) else result.error("CAMERA_ERROR", "Code=$code", null)
                    }
                    "stopNativeCamera" -> {
                        val code = aegisStopHardwareCapture()
                        result.success(code)
                    }
                    else -> result.notImplemented()
                }
            }

        // --- P0-A.8b â€” Updater in-app (P-6) ---
        // ChaÃ®ne de confiance Q22-Q27 :
        //   Q22 : Dart vÃ©rifie ed25519 du manifeste via FFI Rust.
        //   Q23 : Kotlin tÃ©lÃ©charge l'APK (OkHttp, whitelist aresmaxima.com).
        //   Q24 : Kotlin vÃ©rifie SHA-256 en temps constant.
        //   Q25 : Kotlin lance l'installateur via FileProvider.
        //   Q26 : Kotlin vÃ©rifie canRequestPackageInstalls() avant l'Intent.
        //   Q27 : Kotlin supprime l'APK aprÃ¨s consommation du fd par l'installateur.
        val updaterChannel = MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            AegisUpdater.CHANNEL_NAME
        )
        updaterChannel.setMethodCallHandler(AegisUpdater(this, updaterChannel))
    }

    // =====================================================================
    // Capture camÃ©ra
    // =====================================================================

    private fun startCameraInternal() {
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            try {
                cameraProvider = future.get()

                val previewView = getPreviewView()
                if (previewView == null) {
                    Log.e(TAG, "startCameraInternal: pas de PreviewView attachÃ©e")
                    return@addListener
                }

                val preview = Preview.Builder().build()
                preview.setSurfaceProvider(previewView.surfaceProvider)

                val imageAnalysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()

                imageAnalysis.setAnalyzer(cameraExecutor) { image ->
                    try {
                        val yBuf = image.planes[0].buffer
                        val uBuf = image.planes[1].buffer
                        val vBuf = image.planes[2].buffer

                        yPool = toDirectPooled(yBuf, yPool)
                        uPool = toDirectPooled(uBuf, uPool)
                        vPool = toDirectPooled(vBuf, vPool)

                        aegis_ingest_camera_frame_direct(
                            yPool!!, yPool!!.remaining(),
                            uPool!!, uPool!!.remaining(),
                            vPool!!, vPool!!.remaining(),
                            image.width, image.height
                        )
                    } catch (t: Throwable) {
                        Log.e(TAG, "Frame ingest a Ã©chouÃ©", t)
                    } finally {
                        image.close()
                    }
                }

                cameraProvider?.unbindAll()
                cameraProvider?.bindToLifecycle(
                    this as LifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    imageAnalysis
                )
                Log.i(TAG, "CameraX: Preview + ImageAnalysis liÃ©s")
            } catch (e: Exception) {
                Log.e(TAG, "startCamera a Ã©chouÃ©", e)
            }
        }, ContextCompat.getMainExecutor(this))
    }

    private fun toDirectPooled(src: ByteBuffer, pool: ByteBuffer?): ByteBuffer {
        val need = src.remaining()
        val dst = if (pool == null || pool.capacity() < need) {
            ByteBuffer.allocateDirect(need)
        } else {
            pool.clear()
            pool
        }
        dst.put(src.duplicate())
        dst.flip()
        return dst
    }

    // =====================================================================
    // RÃ©sultats d'activitÃ©
    // =====================================================================

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1001) {
            if (resultCode == Activity.RESULT_OK) {
                pendingResult?.success(true)
            } else {
                pendingResult?.error("AUTH_FAILED", "Ã‰chec auth.", null)
            }
            pendingResult = null
        }
    }

    // =====================================================================
    // Callback permission camÃ©ra (filet de sÃ©curitÃ©)
    // =====================================================================

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == CAMERA_PERMISSION_CODE) {
            if (grantResults.isNotEmpty() &&
                grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                Log.i(TAG, "Permission camÃ©ra accordÃ©e â€” dÃ©marrage automatique")
                runOnUiThread { startCameraInternal() }
            } else {
                Log.w(TAG, "Permission camÃ©ra refusÃ©e")
            }
        }
    }
}