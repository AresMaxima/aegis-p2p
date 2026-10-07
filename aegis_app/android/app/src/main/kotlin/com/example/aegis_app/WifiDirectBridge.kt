package com.example.aegis_app

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.wifi.p2p.WifiP2pManager
import android.os.Build
import android.os.Looper
import android.util.Log

/**
 * P0-A.2 (2026-10-07) — Wi-Fi Direct Bridge (Kotlin ↔ Rust).
 *
 * ─────────────────────────────────────────────────────────────────────
 * Politique de sécurité (D3 = manual pairing, D37 = zéro confiance) :
 *
 *   • PAS d'auto-discovery. Aucun broadcast du nom AEGIS.
 *   • Le pairing est déclenché par échange explicite (QR code).
 *   • Le nom Wi-Fi Direct du device est ÉPHÉMÈRE et ALÉATOIRE
 *     (généré à l'init, régénéré à chaque session).
 *   • Un contact est ajouté UNIQUEMENT après un échange OOB validé.
 *
 * ─────────────────────────────────────────────────────────────────────
 * Architecture cible (P0-A.2 complet) :
 *
 *   [Kotlin] WifiP2pManager → découverte ciblée → négociation → Socket
 *                                     ↓
 *                          ParcelFileDescriptor
 *                                     ↓
 *                          JNI (aegis_wifi_direct_socket_fd)
 *                                     ↓
 *   [Rust]  TcpStream::from_raw_fd(fd) → impl EncryptedTransport
 *
 * ─────────────────────────────────────────────────────────────────────
 * Sous-blocs :
 *
 *   • P0-A.2a (cette session) : squelette + permissions + canal + init
 *   • P0-A.2b : peer discovery + group formation (Kotlin)
 *   • P0-A.2c : socket exchange via JNI (Kotlin → Rust)
 *   • P0-A.2d : WifiDirectTransport (Rust)
 *   • P0-A.2e : tests Android instrumentés (2 devices)
 * ─────────────────────────────────────────────────────────────────────
 */
object WifiDirectBridge {

    private const val TAG = "WifiDirectBridge"

    // =====================================================================
    // État interne
    // =====================================================================

    /** WifiP2pManager Android — null si non initialisé. */
    @Volatile
    private var manager: WifiP2pManager? = null

    /** Canal WifiP2p — null si non initialisé. */
    @Volatile
    private var channel: WifiP2pManager.Channel? = null

    /** Receiver Broadcast pour les événements Wi-Fi Direct. */
    @Volatile
    private var receiver: BroadcastReceiver? = null

    /** Contexte Android (application context, leak-safe). */
    @Volatile
    private var appContext: Context? = null

    /** État global d'initialisation. */
    @Volatile
    private var initialized: Boolean = false

    // =====================================================================
    // Détection
    // =====================================================================

    /**
     * Vrai si l'hardware supporte Wi-Fi Direct.
     *
     * Sur certains devices bas de gamme, `FEATURE_WIFI_DIRECT` est absent.
     * Dans ce cas, AEGIS démarre en mode dégradé (BLE + Tor uniquement).
     */
    fun isSupported(context: Context): Boolean {
        return context.packageManager.hasSystemFeature(
            PackageManager.FEATURE_WIFI_DIRECT
        )
    }

    // =====================================================================
    // Initialisation / Arrêt
    // =====================================================================

    /**
     * Initialise le bridge : WifiP2pManager + Channel + BroadcastReceiver.
     *
     * **Doit être appelé dans MainActivity.onCreate()**, après avoir
     * vérifié `isSupported()`.
     *
     * Retourne `true` si l'initialisation a réussi.
     */
    fun initialize(context: Context): Boolean {
        if (initialized) {
            Log.w(TAG, "initialize: déjà initialisé, no-op")
            return true
        }

        if (!isSupported(context)) {
            Log.w(TAG, "Wi-Fi Direct non supporté sur ce device")
            return false
        }

        return try {
            appContext = context.applicationContext

            val mgr = context.getSystemService(Context.WIFI_P2P_SERVICE)
                as? WifiP2pManager
                ?: run {
                    Log.e(TAG, "WIFI_P2P_SERVICE introuvable")
                    return false
                }

            val ch = mgr.initialize(context, Looper.getMainLooper()) {
                Log.e(TAG, "WifiP2pManager.Channel perdu (framework error)")
            }

            if (ch == null) {
                Log.e(TAG, "WifiP2pManager.initialize a retourné null")
                return false
            }

            manager = mgr
            channel = ch
            receiver = createReceiver()
            registerReceiver(context)

            initialized = true
            Log.i(TAG, "Wi-Fi Direct bridge initialisé (manual pairing mode)")
            true
        } catch (t: Throwable) {
            Log.e(TAG, "initialize a échoué", t)
            cleanupInternal()
            false
        }
    }

    /**
     * Relâche toutes les ressources Wi-Fi Direct.
     *
     * **Doit être appelé dans MainActivity.onDestroy()**.
     */
    fun shutdown() {
        if (!initialized) return

        try {
            unregisterReceiver()
        } catch (t: Throwable) {
            Log.w(TAG, "unregisterReceiver a échoué", t)
        }

        cleanupInternal()
        initialized = false
        Log.i(TAG, "Wi-Fi Direct bridge arrêté")
    }

    private fun cleanupInternal() {
        manager = null
        channel = null
        receiver = null
        appContext = null
    }

    // =====================================================================
    // BroadcastReceiver — événements Wi-Fi Direct
    // =====================================================================

    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    private fun registerReceiver(context: Context) {
        val recv = receiver ?: return
        val filter = IntentFilter().apply {
            addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION)
        }

        // API 33+ exige RECEIVER_NOT_EXPORTED pour les receivers internes.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(recv, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(recv, filter)
        }
    }

    private fun unregisterReceiver() {
        val recv = receiver ?: return
        val ctx = appContext ?: return
        try {
            ctx.unregisterReceiver(recv)
        } catch (t: Throwable) {
            Log.w(TAG, "unregisterReceiver (framework)", t)
        }
    }

    private fun createReceiver(): BroadcastReceiver {
        return object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                when (intent.action) {
                    WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION -> {
                        val state = intent.getIntExtra(
                            WifiP2pManager.EXTRA_WIFI_STATE,
                            WifiP2pManager.WIFI_P2P_STATE_DISABLED
                        )
                        val enabled = state == WifiP2pManager.WIFI_P2P_STATE_ENABLED
                        Log.i(TAG, "WIFI_P2P_STATE_CHANGED: enabled=$enabled")
                        // TODO(P0-A.2b) : notifier Flutter via canal
                    }
                    WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION -> {
                        Log.i(TAG, "WIFI_P2P_PEERS_CHANGED")
                        // TODO(P0-A.2b) : requestPeers() + notifier Flutter
                    }
                    WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION -> {
                        Log.i(TAG, "WIFI_P2P_CONNECTION_CHANGED")
                        // TODO(P0-A.2b) : requestConnectionInfo() + notifier
                    }
                    WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION -> {
                        Log.i(TAG, "WIFI_P2P_THIS_DEVICE_CHANGED")
                        // No-op pour l'instant (nom éphémère à gérer P0-A.2b)
                    }
                }
            }
        }
    }

    // =====================================================================
    // Méthodes publiques (stubs — implémentation en P0-A.2b)
    // =====================================================================

    /**
     * État actuel du bridge (pour les tests Dart).
     *
     * Retourne un `Map<String, Any>` :
     *   • supported : Boolean (hardware présent)
     *   • initialized : Boolean (bridge prêt)
     *   • wifi_p2p_enabled : Boolean (Wi-Fi Direct activé par l'utilisateur)
     */
    fun getState(): Map<String, Any> {
        val ctx = appContext
        return mapOf(
            "supported" to (ctx?.let { isSupported(it) } ?: false),
            "initialized" to initialized,
            "wifi_p2p_enabled" to (manager != null && channel != null),
        )
    }

    /**
     * Démarre une découverte **ciblée** vers un peer spécifique (manual pairing).
     *
     * **P0-A.2b** : l'implémentation appellera `manager.discoverPeers()`
     * uniquement après un échange de QR code valide côté Dart.
     *
     * Retourne 0 si OK, code négatif sinon.
     */
    fun startDiscovery(): Int {
        if (!initialized) {
            Log.w(TAG, "startDiscovery: bridge non initialisé")
            return -1
        }
        // TODO(P0-A.2b) : implémenter la découverte ciblée
        Log.i(TAG, "startDiscovery: NOT_IMPLEMENTED (P0-A.2b)")
        return -100
    }

    /**
     * Arrête la découverte en cours.
     *
     * **P0-A.2b**.
     */
    fun stopDiscovery(): Int {
        if (!initialized) return -1
        // TODO(P0-A.2b)
        Log.i(TAG, "stopDiscovery: NOT_IMPLEMENTED (P0-A.2b)")
        return -100
    }

    /**
     * Se connecte à un peer spécifique (manual pairing via QR).
     *
     * **P0-A.2b** : `deviceAddress` est fourni par le QR code scanné.
     */
    fun connectToPeer(deviceAddress: String): Int {
        if (!initialized) return -1
        if (deviceAddress.isEmpty()) {
            Log.w(TAG, "connectToPeer: adresse vide")
            return -2
        }
        // TODO(P0-A.2b) : WifiP2pConfig.Builder + manager.connect()
        Log.i(TAG, "connectToPeer($deviceAddress): NOT_IMPLEMENTED (P0-A.2b)")
        return -100
    }

    /**
     * Déconnecte du peer actif.
     *
     * **P0-A.2b**.
     */
    fun disconnect(): Int {
        if (!initialized) return -1
        // TODO(P0-A.2b)
        Log.i(TAG, "disconnect: NOT_IMPLEMENTED (P0-A.2b)")
        return -100
    }
}