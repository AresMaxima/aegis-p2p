package com.example.aegis_app

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
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
import io.flutter.plugin.common.MethodChannel
import java.nio.ByteBuffer
import java.util.concurrent.Executors

class MainActivity : FlutterActivity() {

    companion object {
        private const val TAG = "AEGIS_MAIN"
        private const val KEYSTORE_CHANNEL = "com.aegis/keystore"
        private const val TEE_UI_CHANNEL   = "com.aegis.p2p/tee_ui"
        private const val CAMERA_CHANNEL   = "com.aegis.p2p/camera"
        private const val CAMERA_PERMISSION_CODE = 1002

        init {
            System.loadLibrary("aegis_core")
        }

        // ─────────────────────────────────────────────────────────────
        // Référence vers le PreviewView CameraX (aperçu live).
        // Renseignée par CameraPreviewView.init(), utilisée par
        // startCameraInternal() pour lier le use case Preview.
        // ─────────────────────────────────────────────────────────────
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
    // Déclarations JNI — Rust (lib.rs)
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
    // Option 2 (audit 2026-09-20) : dérivation de la master_key via HKDF-SHA256.
    // Combine la clé StrongBox (ROOT_KEY côté Rust) et le vault PIN.
    // 0 = OK, -1 = JNI, -2 = PIN vide, -3 = ROOT_KEY manquante, -4 = autre.
    // ---------------------------------------------------------------------
    external fun aegis_derive_and_set_master_key(pin: String): Int

    // ---------------------------------------------------------------------
    // Niveau 3 — Android Key Attestation.
    // Reçoit la chaîne DER concaténée + le challenge (SHA-256 APK).
    // Retourne 0 si OK, un code négatif sinon (Rust purge si compromis).
    // ---------------------------------------------------------------------
    external fun aegis_verify_attestation_chain(
        chain: ByteArray,
        challenge: ByteArray,
    ): Int

    /**
     * Wrapper Kotlin : récupère l'attestation matérielle et la fait
     * vérifier par Rust.
     *
     * 0  = attestation OK
     * -1 = pas de support d'attestation (device legacy)
     * -2 = échec de récupération de la chaîne
     * -3..-N = chaîne compromise (Rust a déjà purgé)
     */
    fun aegisVerifyDeviceAttestation(): Int {
        val data = AttestationVerifier.getAttestationData(this)
            ?: return -2

        return try {
            aegis_verify_attestation_chain(data.chain, data.challenge)
        } catch (t: Throwable) {
            Log.e(TAG, "aegis_verify_attestation_chain a échoué", t)
            -1
        }
    }

    /**
     * N3 (audit 2026-09-20) : détecte si l'APK est signée avec la clé
     * debug standard Android (`CN=Android Debug, O=Android, C=US`).
     *
     * Utilisation : la vérification d'attestation ne peut réussir que si
     * le challenge SHA256(signature APK) correspond à la chaîne d'attestation
     * StrongBox. En mode debug, le challenge mismatch est inévitable → on
     * skip l'attestation pour permettre le développement.
     *
     * En mode release officiel (avec la clé de signature de production),
     * le challenge sera correct et l'attestation ACTIVE.
     *
     * Robuste à tous les cas : impossible de "tricher" sur un flag Gradle —
     * on lit la signature réelle du package.
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
            Log.e(TAG, "Impossible de vérifier la signature de l'APK", e)
            // En cas de doute : considérer release-signed (strict).
            false
        }
    }

    // =====================================================================
    // État interne
    // =====================================================================

    private lateinit var protectedConfirmation: ProtectedConfirmation
    private var pendingResult: MethodChannel.Result? = null
    private val cameraExecutor = Executors.newSingleThreadExecutor()
    private var cameraProvider: ProcessCameraProvider? = null

    private var yPool: ByteBuffer? = null
    private var uPool: ByteBuffer? = null
    private var vPool: ByteBuffer? = null

    // =====================================================================
    // Cycle de vie
    // =====================================================================

    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)

        // CRUCIAL : enregistrer l'instance AVANT tout appel de aegis_capture_ndk_camera.
        try {
            aegisRegisterMainActivity(this)
        } catch (t: Throwable) {
            Log.e(TAG, "aegisRegisterMainActivity a échoué", t)
        }

        // ============================================================
        // N3 (audit 2026-09-20) : politique d'attestation automatique.
        // ============================================================
        //   • APK signée avec la clé DEBUG Android → attestation SKIPPED.
        //     Raison : la clé StrongBox a été générée avec un challenge
        //     différent de SHA256(signature APK debug). Toute vérification
        //     échouerait avec ChallengeMismatch → PanicPurge → kill.
        //
        //   • APK signée avec la clé RELEASE officielle → attestation ACTIVE.
        //     Le challenge SHA256(signature APK release) sera correctement
        //     comparé à la chaîne d'attestation StrongBox.
        // ============================================================
        val isDebugSigned = isSignedWithDebugKey()
        if (isDebugSigned) {
            Log.w(TAG, "APK signée avec clé DEBUG — ATTESTATION SKIPPED (mode dev)")
        } else {
            Log.i(TAG, "APK release-signée — ATTESTATION ACTIVE")
            try {
                val attestationResult = aegisVerifyDeviceAttestation()
                Log.i(TAG, "Attestation result: $attestationResult")
                if (attestationResult < 0) {
                    Log.e(TAG, "Attestation compromise (code=$attestationResult)")
                }
            } catch (t: Throwable) {
                Log.e(TAG, "Attestation verification a échoué", t)
            }
        }
    }

    override fun onDestroy() {
        try { cameraProvider?.unbindAll() } catch (_: Throwable) {}
        try { aegis_release_surface() } catch (_: Throwable) {}
        cameraExecutor.shutdown()
        super.onDestroy()
    }

    // =====================================================================
    // Méthode appelée depuis Rust via JNI (aegis_capture_ndk_camera)
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
            Log.e(TAG, "aegisStartHardwareCapture a échoué", t)
            -1
        }
    }

    /**
     * Arrête la capture caméra (débind tous les use cases).
     * Appelée par Flutter quand l'utilisateur tape CAPTURER ou ANNULER.
     */
    fun aegisStopHardwareCapture(): Int {
        return try {
            cameraProvider?.unbindAll()
            Log.i(TAG, "CameraX: unbindAll (stop hardware capture)")
            0
        } catch (t: Throwable) {
            Log.e(TAG, "aegisStopHardwareCapture a échoué", t)
            -1
        }
    }

    // =====================================================================
    // Flutter Engine
    // =====================================================================

    override fun configureFlutterEngine(@NonNull flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        protectedConfirmation = ProtectedConfirmation(this)

        // PlatformView : surface VRAM (BlindView).
        flutterEngine.platformViewsController.registry.registerViewFactory(
            "com.aegis.p2p/blind_surface",
            BlindViewFactory()
        )

        // PlatformView : aperçu caméra live (CameraPreviewView).
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
                                    result.error(
                                        "TEE_ERROR",
                                        "Taille secrète invalide: ${hw.secret.size} (attendu 32)",
                                        null
                                    )
                                }
                            }
                            is HardwareKeystore.HardwareSecretResult.Failure -> {
                                Log.e(TAG, "Hardware secret indisponible: ${hw.reason} (niveau=${hw.lastKnownLevel})")
                                result.error("TEE_ERROR", hw.reason, null)
                            }
                        }
                    }

                    "deriveMasterKey" -> {
                        // Option 2 (audit 2026-09-20) : combine ROOT_KEY (StrongBox,
                        // déjà stockée côté Rust) + vault PIN → master_key via HKDF-SHA256.
                        val pin = call.argument<String>("pin")
                        if (pin.isNullOrEmpty()) {
                            result.error("MASTER_ERROR", "PIN vide", null)
                            return@setMethodCallHandler
                        }

                        val rc = aegis_derive_and_set_master_key(pin)
                        if (rc == 0) {
                            Log.i(TAG, "Master key dérivée (HKDF-SHA256) — PIN combiné StrongBox")
                            result.success(true)
                        } else {
                            Log.e(TAG, "deriveMasterKey a échoué: rc=$rc")
                            result.error("MASTER_ERROR", "rc=$rc", null)
                        }
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
                            result.error("UNSECURE_DEVICE", "Aucun PIN système.", null)
                        }
                    }
                    "triggerPanic" -> {
                        protectedConfirmation.triggerCrisisBurn()
                        result.success(true)
                    }
                    else -> result.notImplemented()
                }
            }

        // --- Canal caméra native ---
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CAMERA_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "startNativeCamera" -> {
                        val code = aegisStartHardwareCapture()
                        if (code == 0) result.success(0)
                        else result.error("CAMERA_ERROR", "Code=$code", null)
                    }
                    "stopNativeCamera" -> {
                        val code = aegisStopHardwareCapture()
                        result.success(code)
                    }
                    else -> result.notImplemented()
                }
            }
    }

    // =====================================================================
    // Capture caméra
    // =====================================================================

    private fun startCameraInternal() {
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            try {
                cameraProvider = future.get()

                // ─────────────────────────────────────────────────────
                // Use case 1 : PREVIEW (aperçu live à l'écran)
                // ─────────────────────────────────────────────────────
                val previewView = getPreviewView()
                if (previewView == null) {
                    Log.e(TAG, "startCameraInternal: pas de PreviewView attachée")
                    return@addListener
                }

                val preview = Preview.Builder().build()
                preview.setSurfaceProvider(previewView.surfaceProvider)

                // ─────────────────────────────────────────────────────
                // Use case 2 : IMAGE ANALYSIS (frames YUV → Rust)
                // ─────────────────────────────────────────────────────
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
                        Log.e(TAG, "Frame ingest a échoué", t)
                    } finally {
                        image.close()
                    }
                }

                cameraProvider?.unbindAll()
                cameraProvider?.bindToLifecycle(
                    this as LifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,        // ← aperçu visible
                    imageAnalysis   // ← capture en RAM
                )
                Log.i(TAG, "CameraX: Preview + ImageAnalysis liés")
            } catch (e: Exception) {
                Log.e(TAG, "startCamera a échoué", e)
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
    // Résultats d'activité
    // =====================================================================

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1001) {
            if (resultCode == Activity.RESULT_OK) {
                pendingResult?.success(true)
            } else {
                pendingResult?.error("AUTH_FAILED", "Échec auth.", null)
            }
            pendingResult = null
        }
    }

    // =====================================================================
    // Callback permission caméra (filet de sécurité)
    // =====================================================================
    //
    // NOTE : permission_handler côté Dart gère désormais le dialog de
    // permission AVANT d'ouvrir CameraCaptureScreen. Ce callback reste
    // en filet de sécurité si un autre chemin déclenche requestPermissions.

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == CAMERA_PERMISSION_CODE) {
            if (grantResults.isNotEmpty() &&
                grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                Log.i(TAG, "Permission caméra accordée — démarrage automatique")
                runOnUiThread { startCameraInternal() }
            } else {
                Log.w(TAG, "Permission caméra refusée")
            }
        }
    }
}