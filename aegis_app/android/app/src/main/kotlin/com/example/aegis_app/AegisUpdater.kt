package com.example.aegis_app

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.Log
import androidx.core.content.FileProvider
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/**
 * P0-A.8b — Updater in-app (P-6).
 *
 * Chaîne de confiance (Q22-Q27) :
 *   Q22 — Dart fetch + vérifie ed25519 du manifeste via FFI Rust.
 *   Q23 — Kotlin télécharge l'APK (OkHttp, whitelist aresmaxima.com, no redirect).
 *   Q24 — Kotlin calcule SHA-256 streaming + compare en temps constant.
 *   Q25 — Kotlin lance l'installateur via FileProvider + content:// URI.
 *   Q26 — Kotlin vérifie canRequestPackageInstalls() avant de lancer.
 *   Q27 — Kotlin supprime l'APK après que l'installateur a consommé le fd.
 *
 * Codes de retour (symétriques côté Dart) :
 *   RC_OK               =  0 (Intent d'installation lancé)
 *   RC_NETWORK_ERROR    = -1 (OkHttp / HTTP non-2xx / timeout)
 *   RC_HASH_MISMATCH    = -2 (SHA-256 ne correspond pas au manifeste)
 *   RC_PERMISSION_DENIED= -3 (REQUEST_INSTALL_PACKAGES non accordée)
 *   RC_IO_ERROR         = -4 (écriture fichier / rename)
 *   RC_INVALID_URL      = -5 (scheme != https ou host != aresmaxima.com)
 *   RC_ALREADY_RUNNING  = -6 (un download est déjà en cours)
 *   RC_SIZE_EXCEEDED    = -8 (APK > 200 MB — protection anti-DoS)
 */
class AegisUpdater(
    private val activity: Activity,
    private val channel: MethodChannel,
) : MethodChannel.MethodCallHandler {

    companion object {
        const val CHANNEL_NAME = "com.aegis/updater"
        private const val TAG = "AegisUpdater"

        // Q23 : whitelist stricte
        private const val ALLOWED_HOST = "aresmaxima.com"

        // Anti-DoS : un APK AEGIS fait ~44 MB, 200 MB est une marge de sécurité
        private const val MAX_APK_BYTES = 200L * 1024 * 1024

        // Callback de progression tous les 256 KB (≈ 170 callbacks pour 44 MB)
        private const val PROGRESS_INTERVAL_BYTES = 256L * 1024

        // Codes de retour
        const val RC_OK = 0
        const val RC_NETWORK_ERROR = -1
        const val RC_HASH_MISMATCH = -2
        const val RC_PERMISSION_DENIED = -3
        const val RC_IO_ERROR = -4
        const val RC_INVALID_URL = -5
        const val RC_ALREADY_RUNNING = -6
        const val RC_SIZE_EXCEEDED = -8
    }

    private val mainHandler = Handler(Looper.getMainLooper())

    // Q23 : TLS strict (pas de downgrade), timeouts, pas de redirect.
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
        .followRedirects(false)
        .followSslRedirects(false)
        .retryOnConnectionFailure(false)
        .build()

    @Volatile
    private var inFlight: Boolean = false

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "downloadAndInstall" -> {
                val apkUrl = call.argument<String>("apkUrl")
                val expectedSha256 = call.argument<String>("expectedSha256Hex")
                val version = call.argument<String>("version")
                if (apkUrl.isNullOrBlank() || expectedSha256.isNullOrBlank() || version.isNullOrBlank()) {
                    result.error("INVALID_ARGS", "apkUrl, expectedSha256Hex and version are required", null)
                    return
                }
                handleDownloadAndInstall(apkUrl, expectedSha256, version, result)
            }
            "canRequestPackageInstalls" -> result.success(canRequestPackageInstalls())
            "openUnknownSourcesSettings" -> {
                openUnknownSourcesSettings()
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Q26 : vérification runtime de la permission
    // ─────────────────────────────────────────────────────────────
    private fun canRequestPackageInstalls(): Boolean {
        return if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            activity.packageManager.canRequestPackageInstalls()
        } else {
            @Suppress("DEPRECATION")
            Settings.Secure.getInt(
                activity.contentResolver,
                Settings.Secure.INSTALL_NON_MARKET_APPS,
                0
            ) == 1
        }
    }

    private fun openUnknownSourcesSettings() {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            val intent = Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES)
                .setData(Uri.parse("package:${activity.packageName}"))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            activity.startActivity(intent)
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Q23 + Q24 + Q25 + Q27 : pipeline complet
    // ─────────────────────────────────────────────────────────────
    private fun handleDownloadAndInstall(
        apkUrl: String,
        expectedSha256: String,
        version: String,
        result: MethodChannel.Result,
    ) {
        if (inFlight) {
            result.error("ALREADY_RUNNING", "Updater already running", RC_ALREADY_RUNNING)
            return
        }
        inFlight = true

        Thread {
            var rc = RC_OK
            var tmpFile: File? = null
            var apkFile: File? = null

            try {
                // ─── Q23 : validation stricte de l'URL ───────────────
                val uri = Uri.parse(apkUrl)
                val host = uri.host
                if (uri.scheme != "https" || host == null || !host.equals(ALLOWED_HOST, ignoreCase = true)) {
                    rc = RC_INVALID_URL
                    throw SecurityException("URL rejected (scheme/host): $apkUrl")
                }

                // ─── Q26 : permission runtime ────────────────────────
                if (!canRequestPackageInstalls()) {
                    rc = RC_PERMISSION_DENIED
                    throw SecurityException("REQUEST_INSTALL_PACKAGES not granted")
                }

                // ─── Préparation du cache ────────────────────────────
                val updatesDir = File(activity.cacheDir, "updates").also { it.mkdirs() }
                apkFile = File(updatesDir, "aegis-$version.apk")
                tmpFile = File(updatesDir, "aegis-$version.apk.tmp")
                if (tmpFile.exists()) tmpFile.delete()
                if (apkFile.exists()) apkFile.delete()

                // ─── Q23 + Q24 : download + hash streaming ───────────
                val digest = MessageDigest.getInstance("SHA-256")
                var bytesRead = 0L
                var lastProgress = 0L

                val request = Request.Builder().url(apkUrl).get().build()
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        rc = RC_NETWORK_ERROR
                        throw RuntimeException("HTTP ${response.code}")
                    }
                    val body = response.body
                        ?: run {
                            rc = RC_NETWORK_ERROR
                            throw RuntimeException("Null response body")
                        }
                    val contentLength = body.contentLength()
                    if (contentLength > MAX_APK_BYTES) {
                        rc = RC_SIZE_EXCEEDED
                        throw RuntimeException("Content-Length too large: $contentLength")
                    }

                    FileOutputStream(tmpFile).use { out ->
                        body.byteStream().use { input ->
                            val buf = ByteArray(8192)
                            while (true) {
                                val n = input.read(buf)
                                if (n < 0) break
                                out.write(buf, 0, n)
                                digest.update(buf, 0, n)
                                bytesRead += n
                                if (bytesRead > MAX_APK_BYTES) {
                                    rc = RC_SIZE_EXCEEDED
                                    throw RuntimeException("APK size exceeded during streaming")
                                }
                                if (bytesRead - lastProgress >= PROGRESS_INTERVAL_BYTES) {
                                    lastProgress = bytesRead
                                    publishProgress(bytesRead, contentLength)
                                }
                            }
                        }
                        out.fd.sync()
                    }
                }

                // ─── Q24 : vérification SHA-256 (temps constant) ─────
                val computed = digest.digest()
                val expected = hexToBytes(expectedSha256)
                    ?: run {
                        rc = RC_HASH_MISMATCH
                        throw SecurityException("Expected hash is not valid hex/64 chars")
                    }
                if (!MessageDigest.isEqual(computed, expected)) {
                    rc = RC_HASH_MISMATCH
                    throw SecurityException("SHA-256 mismatch")
                }

                // ─── Rename atomique ─────────────────────────────────
                if (!tmpFile.renameTo(apkFile)) {
                    rc = RC_IO_ERROR
                    throw RuntimeException("Atomic rename failed")
                }
                tmpFile = null // ownership transférée à apkFile

                // ─── Q25 : lancement de l'installateur ───────────────
                launchInstaller(apkFile)

                // ─── Q27 : cleanup différé (installateur a consommé fd)
                val toDelete = apkFile
                mainHandler.postDelayed({
                    try {
                        if (toDelete.exists()) {
                            val ok = toDelete.delete()
                            Log.i(TAG, "Post-install cleanup: deleted=$ok")
                        }
                    } catch (t: Throwable) {
                        Log.w(TAG, "Post-install cleanup failed", t)
                    }
                }, 2000L)

                mainHandler.post { result.success(RC_OK) }
            } catch (t: Throwable) {
                Log.e(TAG, "Update failed (rc=$rc): ${t.message}", t)
                try { tmpFile?.delete() } catch (_: Throwable) {}
                val finalRc = rc
                val msg = t.message ?: t.javaClass.simpleName
                mainHandler.post { result.error("UPDATE_FAILED", msg, finalRc) }
            } finally {
                inFlight = false
            }
        }.start()
    }

    // ─────────────────────────────────────────────────────────────
    // Q25 : FileProvider + Intent install
    // ─────────────────────────────────────────────────────────────
    private fun launchInstaller(apkFile: File) {
        val authority = "${activity.packageName}.updater.fileprovider"
        val uri: Uri = FileProvider.getUriForFile(activity, authority, apkFile)
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        activity.startActivity(intent)
    }

    // ─────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────
    private fun publishProgress(downloaded: Long, total: Long) {
        mainHandler.post {
            channel.invokeMethod("onProgress", mapOf(
                "downloaded" to downloaded,
                "total" to total,
            ))
        }
    }

    private fun hexToBytes(hex: String): ByteArray? {
        val clean = hex.trim().lowercase()
        if (clean.length != 64) return null
        val out = ByteArray(32)
        for (i in 0 until 32) {
            val hi = Character.digit(clean[i * 2], 16)
            val lo = Character.digit(clean[i * 2 + 1], 16)
            if (hi < 0 || lo < 0) return null
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }
}