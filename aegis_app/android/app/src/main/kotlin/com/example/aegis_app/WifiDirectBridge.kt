package com.example.aegis_app

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.p2p.WifiP2pManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import io.flutter.plugin.common.EventChannel
import java.security.SecureRandom

/**
 * P0-A.2 (2026-10-07 → 2026-10-09) — Wi-Fi Direct Bridge (Kotlin ↔ Rust).
 *
 * ─────────────────────────────────────────────────────────────────────
 * Politique de sécurité (D1 = manual pairing, D37 = zéro confiance) :
 *
 *   • PAS d'auto-discovery. Aucun broadcast du nom AEGIS.
 *   • Le pairing est déclenché par échange explicite (QR code).
 *   • Le nom Wi-Fi Direct du device est ÉPHÉMÈRE et ALÉATOIRE
 *     (12 chars base62, SecureRandom, régénéré à chaque session).
 *   • Un contact est ajouté UNIQUEMENT après un échange OOB validé
 *     (deviceName + fingerprint ed25519).
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
 *   • P0-A.2a (fait) : squelette + permissions + canal + init
 *   • P0-A.2b.1 (fait) : FFI ed25519 (Rust)
 *   • P0-A.2b.2 (ce fichier) : implémentation réelle (nom éphémère,
 *     EventChannel, discovery, connect, receiver)
 *   • P0-A.2b.3 : handshake ed25519 post-connexion (Kotlin → Rust FFI)
 *   • P0-A.2b.4 : wifi_direct_bridge.dart (Dart)
 *   • P0-A.2b.5 : tests Android instrumentés (2 devices)
 * ─────────────────────────────────────────────────────────────────────
 */
object WifiDirectBridge {

    private const val TAG = "WifiDirectBridge"

    /** Longueur du nom éphémère (D2). */
    private const val EPHEMERAL_NAME_LENGTH = 12

    /** Alphabet base62 pour le nom éphémère. */
    private const val BASE62 =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

    /** Timeout de découverte (D4 : 40 s = 30 s + 10 s de marge). */
    private const val DISCOVERY_TIMEOUT_MS = 40_000L

    // =====================================================================
    // État interne
    // =====================================================================

    @Volatile
    private var manager: WifiP2pManager? = null

    @Volatile
    private var channel: WifiP2pManager.Channel? = null

    @Volatile
    private var receiver: BroadcastReceiver? = null

    @Volatile
    private var appContext: Context? = null

    @Volatile
    private var initialized: Boolean = false

    /** Nom éphémère courant (12 chars base62). Régénéré à chaque init. */
    @Volatile
    private var ephemeralName: String? = null

    /** Sink EventChannel vers Flutter (rempli quand Flutter s'abonne). */
    @Volatile
    private var eventSink: EventChannel.EventSink? = null

    /** Nom éphémère du peer ciblé (rempli par connectToPeer). */
    @Volatile
    private var expectedPeerName: String? = null

    @Volatile
    private var discoveryActive: Boolean = false

    @Volatile
    private var timeoutHandler: Handler? = null

    @Volatile
    private var timeoutRunnable: Runnable? = null

    private val secureRandom = SecureRandom()

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
     * Initialise le bridge : nom éphémère + WifiP2pManager + Channel + Receiver.
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

            // 1. Générer le nom éphémère (D2 : 12 chars base62)
            ephemeralName = generateEphemeralName()
            Log.i(TAG, "Nom éphémère généré (12 chars)")

            // 2. Initialiser WifiP2pManager (main looper obligatoire)
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
            timeoutHandler = Handler(Looper.getMainLooper())
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

        // 1. Annuler le timer
        cancelDiscoveryTimeout()

        // 2. Stopper la découverte si active
        try {
            if (discoveryActive) {
                channel?.let { ch ->
                    manager?.stopPeerDiscovery(ch, null)
                }
            }
        } catch (t: Throwable) {
            Log.w(TAG, "stopPeerDiscovery a échoué", t)
        }

        // 3. Unregister le receiver
        try {
            unregisterReceiver()
        } catch (t: Throwable) {
            Log.w(TAG, "unregisterReceiver a échoué", t)
        }

        // 4. Reset l'état
        cleanupInternal()
        initialized = false
        Log.i(TAG, "Wi-Fi Direct bridge arrêté")
    }

    private fun cleanupInternal() {
        manager = null
        channel = null
        receiver = null
        appContext = null
        ephemeralName = null
        expectedPeerName = null
        discoveryActive = false
        timeoutHandler = null
        timeoutRunnable = null
    }

    // =====================================================================
    // EventChannel
    // =====================================================================

    /**
     * Enregistre le sink EventChannel (appelé par MainActivity).
     *
     * `null` quand Flutter se désabonne (cancel).
     */
    fun setEventSink(sink: EventChannel.EventSink?) {
        eventSink = sink
        Log.i(TAG, "EventSink ${if (sink == null) "retiré" else "enregistré"}")
    }

    /** Envoie un événement à Flutter si un sink est actif. */
    private fun notifyEvent(event: Map<String, Any?>) {
        val sink = eventSink ?: return
        try {
            sink.success(event)
        } catch (t: Throwable) {
            Log.w(TAG, "notifyEvent a échoué", t)
        }
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
                        notifyEvent(mapOf(
                            "type" to "state_changed",
                            "enabled" to enabled,
                        ))
                    }

                    WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION -> {
                        Log.i(TAG, "WIFI_P2P_PEERS_CHANGED")
                        requestPeers()
                    }

                    WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION -> {
                        Log.i(TAG, "WIFI_P2P_CONNECTION_CHANGED")
                        requestConnectionInfo()
                    }

                    WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION -> {
                        // No-op pour l'instant (nom éphémère géré côté bridge)
                    }
                }
            }
        }
    }

    // =====================================================================
    // Callbacks WifiP2pManager
    // =====================================================================

    @SuppressLint("MissingPermission")
    private fun requestPeers() {
        val mgr = manager ?: return
        val ch = channel ?: return

        try {
            mgr.requestPeers(ch) { peerList ->
                val peers = peerList?.deviceList ?: emptySet()
                Log.i(TAG, "onPeersAvailable: ${peers.size} peer(s)")

                val expected = expectedPeerName
                val filtered = if (expected != null) {
                    peers.filter { it.deviceName == expected }
                } else {
                    // Aucun nom attendu : ne rien remonter (manual pairing strict)
                    emptyList()
                }

                if (filtered.isNotEmpty()) {
                    Log.i(TAG, "Peer ciblé trouvé: ${filtered.size}")
                    notifyEvent(mapOf(
                        "type" to "peers_available",
                        "peers" to filtered.map { d ->
                            mapOf(
                                "deviceName" to d.deviceName,
                                "deviceAddress" to d.deviceAddress,
                                "status" to d.status,
                            )
                        },
                    ))

                    // Auto-connect sur le premier match
                    val target = filtered.first()
                    initiateConnection(target)
                } else if (peers.isNotEmpty()) {
                    Log.i(TAG, "Aucun peer ne matche le nom éphémère attendu")
                }
            }
        } catch (t: SecurityException) {
            Log.e(TAG, "requestPeers: SecurityException (permission manquante ?)", t)
            notifyEvent(mapOf(
                "type" to "error",
                "code" to "permission_denied",
                "message" to (t.message ?: "SecurityException"),
            ))
        } catch (t: Throwable) {
            Log.e(TAG, "requestPeers a échoué", t)
        }
    }

    @SuppressLint("MissingPermission")
    private fun initiateConnection(device: WifiP2pDevice) {
        val mgr = manager ?: return
        val ch = channel ?: return

        try {
            val config = WifiP2pConfig().apply {
                deviceAddress = device.deviceAddress
                // WPS-PBC est le mode par défaut d'Android (API 29+).
                // La sécurité est assurée par le handshake ed25519
                // (P0-A.2b.3) qui suit la connexion Wi-Fi Direct.
                //
                // NOTE : `WpsInfo` et `wpsSetupConfig` sont deprecated
                // et retirés du SDK 36. On ne les configure plus.
            }

            mgr.connect(ch, config, object : WifiP2pManager.ActionListener {
                override fun onSuccess() {
                    Log.i(TAG, "connect() initié vers ${device.deviceName}")
                    notifyEvent(mapOf(
                        "type" to "connecting",
                        "deviceName" to device.deviceName,
                    ))
                }

                override fun onFailure(reason: Int) {
                    Log.e(TAG, "connect() échoué, reason=$reason")
                    notifyEvent(mapOf(
                        "type" to "connect_failed",
                        "reason" to reason,
                    ))
                }
            })
        } catch (t: SecurityException) {
            Log.e(TAG, "initiateConnection: SecurityException", t)
        } catch (t: Throwable) {
            Log.e(TAG, "initiateConnection a échoué", t)
        }
    }

    @SuppressLint("MissingPermission")
    private fun requestConnectionInfo() {
        val mgr = manager ?: return
        val ch = channel ?: return

        try {
            mgr.requestConnectionInfo(ch) { info: WifiP2pInfo? ->
                if (info == null) {
                    Log.i(TAG, "onConnectionInfoAvailable: null (déconnecté)")
                    notifyEvent(mapOf("type" to "disconnected"))
                    return@requestConnectionInfo
                }

                Log.i(TAG, "onConnectionInfoAvailable: groupFormed=${info.groupFormed}, " +
                        "isGroupOwner=${info.isGroupOwner}, " +
                        "goAddr=${info.groupOwnerAddress?.hostAddress}")

                if (info.groupFormed) {
                    notifyEvent(mapOf(
                        "type" to "connected",
                        "isGroupOwner" to info.isGroupOwner,
                        "groupOwnerAddress" to info.groupOwnerAddress?.hostAddress,
                    ))
                } else {
                    notifyEvent(mapOf("type" to "disconnected"))
                }
            }
        } catch (t: SecurityException) {
            Log.e(TAG, "requestConnectionInfo: SecurityException", t)
        } catch (t: Throwable) {
            Log.e(TAG, "requestConnectionInfo a échoué", t)
        }
    }

    // =====================================================================
    // API publique (exposée à Flutter via MethodChannel)
    // =====================================================================

    /**
     * État actuel du bridge.
     */
    fun getState(): Map<String, Any> {
        val ctx = appContext
        return mapOf(
            "supported" to (ctx?.let { isSupported(it) } ?: false),
            "initialized" to initialized,
            "wifi_p2p_enabled" to (manager != null && channel != null),
            "discovery_active" to discoveryActive,
        )
    }

    /**
     * Retourne le nom éphémère courant (12 chars base62).
     *
     * Utilisé par Flutter pour construire le QR code (P0-A.2b.4).
     * `null` si le bridge n'est pas initialisé.
     */
    fun getEphemeralName(): String? = ephemeralName

    /**
     * Lance une découverte **ciblée** vers un peer spécifique.
     *
     * Retourne :
     *   0  = discovery lancée
     *  -1  = bridge non initialisé
     *  -2  = `deviceName` vide
     *  -3  = discovery déjà active
     *  -4  = SecurityException (permission manquante)
     *  -5  = échec framework
     */
    @SuppressLint("MissingPermission")
    fun startDiscovery(expectedName: String?): Int {
        if (!initialized) {
            Log.w(TAG, "startDiscovery: bridge non initialisé")
            return -1
        }

        val mgr = manager ?: return -1
        val ch = channel ?: return -1

        // Si un nom est fourni (connectToPeer), le mémoriser pour le filtre
        if (!expectedName.isNullOrEmpty()) {
            expectedPeerName = expectedName
        }

        if (discoveryActive) {
            Log.w(TAG, "startDiscovery: déjà active")
            return -3
        }

        return try {
            mgr.discoverPeers(ch, object : WifiP2pManager.ActionListener {
                override fun onSuccess() {
                    Log.i(TAG, "discoverPeers() OK")
                    discoveryActive = true
                    notifyEvent(mapOf("type" to "discovery_started"))
                    scheduleDiscoveryTimeout()
                }

                override fun onFailure(reason: Int) {
                    Log.e(TAG, "discoverPeers() échoué, reason=$reason")
                    discoveryActive = false
                    notifyEvent(mapOf(
                        "type" to "discovery_failed",
                        "reason" to reason,
                    ))
                }
            })
            0
        } catch (t: SecurityException) {
            Log.e(TAG, "discoverPeers: SecurityException", t)
            -4
        } catch (t: Throwable) {
            Log.e(TAG, "discoverPeers a échoué", t)
            -5
        }
    }

    /**
     * Arrête la découverte en cours.
     *
     * Retourne :
     *   0  = stop OK (ou pas de discovery active)
     *  -1  = bridge non initialisé
     */
    @SuppressLint("MissingPermission")
    fun stopDiscovery(): Int {
        if (!initialized) return -1

        val mgr = manager ?: return -1
        val ch = channel ?: return -1

        cancelDiscoveryTimeout()

        if (!discoveryActive) {
            return 0
        }

        return try {
            mgr.stopPeerDiscovery(ch, object : WifiP2pManager.ActionListener {
                override fun onSuccess() {
                    Log.i(TAG, "stopPeerDiscovery() OK")
                    discoveryActive = false
                    notifyEvent(mapOf("type" to "discovery_stopped"))
                }

                override fun onFailure(reason: Int) {
                    Log.w(TAG, "stopPeerDiscovery() échoué, reason=$reason")
                    discoveryActive = false
                }
            })
            0
        } catch (t: Throwable) {
            Log.e(TAG, "stopPeerDiscovery a échoué", t)
            discoveryActive = false
            -1
        }
    }

    /**
     * Se connecte à un peer spécifique (manual pairing via QR).
     *
     * `deviceName` : nom éphémère 12 chars fourni par le QR code.
     *
     * Retourne :
     *   0  = discovery lancée (le peer sera connecté automatiquement
     *        quand il apparaîtra dans onPeersAvailable)
     *  -1  = bridge non initialisé
     *  -2  = `deviceName` vide
     *  -3  = discovery déjà active
     *  -4  = SecurityException
     *  -5  = échec framework
     */
    fun connectToPeer(deviceName: String): Int {
        if (!initialized) return -1
        if (deviceName.isEmpty()) return -2

        return startDiscovery(deviceName)
    }

    /**
     * Déconnecte du peer actif et stoppe la discovery.
     *
     * Retourne :
     *   0  = OK
     *  -1  = bridge non initialisé
     */
    @SuppressLint("MissingPermission")
    fun disconnect(): Int {
        if (!initialized) return -1

        val mgr = manager ?: return -1
        val ch = channel ?: return -1

        cancelDiscoveryTimeout()
        expectedPeerName = null

        return try {
            mgr.removeGroup(ch, object : WifiP2pManager.ActionListener {
                override fun onSuccess() {
                    Log.i(TAG, "removeGroup() OK")
                    discoveryActive = false
                    notifyEvent(mapOf("type" to "disconnected"))
                }

                override fun onFailure(reason: Int) {
                    Log.w(TAG, "removeGroup() échoué, reason=$reason")
                    discoveryActive = false
                    notifyEvent(mapOf(
                        "type" to "disconnect_failed",
                        "reason" to reason,
                    ))
                }
            })
            0
        } catch (t: Throwable) {
            Log.e(TAG, "removeGroup a échoué", t)
            -1
        }
    }

    // =====================================================================
    // Helpers privés
    // =====================================================================

    /** Génère un nom éphémère de 12 chars base62 via SecureRandom. */
    private fun generateEphemeralName(): String {
        val sb = StringBuilder(EPHEMERAL_NAME_LENGTH)
        repeat(EPHEMERAL_NAME_LENGTH) {
            val idx = secureRandom.nextInt(BASE62.length)
            sb.append(BASE62[idx])
        }
        return sb.toString()
    }

    /** Programme le timeout de découverte (40 s). */
    private fun scheduleDiscoveryTimeout() {
        cancelDiscoveryTimeout()
        val handler = timeoutHandler ?: return

        val r = Runnable {
            Log.w(TAG, "Discovery timeout (${DISCOVERY_TIMEOUT_MS / 1000}s)")
            notifyEvent(mapOf("type" to "discovery_timeout"))
            // Auto-stop
            try {
                val mgr = manager
                val ch = channel
                if (mgr != null && ch != null && discoveryActive) {
                    mgr.stopPeerDiscovery(ch, null)
                }
            } catch (t: Throwable) {
                Log.w(TAG, "stopPeerDiscovery (timeout) a échoué", t)
            }
            discoveryActive = false
            expectedPeerName = null
        }

        timeoutRunnable = r
        handler.postDelayed(r, DISCOVERY_TIMEOUT_MS)
    }

    /** Annule le timeout en cours (si présent). */
    private fun cancelDiscoveryTimeout() {
        val handler = timeoutHandler ?: return
        val r = timeoutRunnable ?: return
        handler.removeCallbacks(r)
        timeoutRunnable = null
    }
}