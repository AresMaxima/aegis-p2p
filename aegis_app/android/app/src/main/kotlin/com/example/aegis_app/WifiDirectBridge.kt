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
import android.os.ParcelFileDescriptor
import android.util.Log
import io.flutter.plugin.common.EventChannel
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.Executors

/**
 * P0-A.2 (2026-10-07 → 2026-10-10) — Wi-Fi Direct Bridge (Kotlin ↔ Rust).
 *
 * ─────────────────────────────────────────────────────────────────────
 * Politique de sécurité (D1 = manual pairing, D37 = zéro confiance) :
 *
 *   • PAS d'auto-discovery. Aucun broadcast du nom AEGIS.
 *   • Le pairing est déclenché par échange explicite (QR code).
 *   • Le nom Wi-Fi Direct du device est ÉPHÉMÈRE et ALÉATOIRE
 *     (12 chars base62, SecureRandom, régénéré à chaque session).
 *   • Un contact est ajouté UNIQUEMENT après un échange OOB validé
 *     (deviceName + fingerprint ed25519 + port).
 *   • Handshake ed25519 symétrique (bidirectionnel) après connexion
 *     → résiste au MITM au premier contact.
 *
 * ─────────────────────────────────────────────────────────────────────
 * Architecture (P0-A.2b.3a) :
 *
 *   [Affiche QR]                    [Scanne QR]
 *   deviceName_A                    deviceName_A (connu)
 *   fingerprint_A                   fingerprint_A (connu)
 *   port_A         ───────────────→ port_A (connu)
 *
 *   Wi-Fi Direct connect → GO ouvre ServerSocket(port_A)
 *                        → Client se connecte à GO:port_A
 *                        → fd transmis à Rust via aegis_wifi_direct_set_fd
 *                        → handshake ed25519 sur ce socket (P0-A.2b.3c)
 *
 * ─────────────────────────────────────────────────────────────────────
 * Sous-blocs :
 *
 *   • P0-A.2a (fait) : squelette + permissions + canal + init
 *   • P0-A.2b.1 (fait) : FFI ed25519 (Rust)
 *   • P0-A.2b.2 (fait) : nom éphémère + EventChannel + discovery
 *   • P0-A.2b.3a (ce fichier) : socket exchange + JNI fd
 *   • P0-A.2b.3b : WifiDirectTransport (Rust)
 *   • P0-A.2b.3c : handshake ed25519 sur socket
 *   • P0-A.2b.4 : wifi_direct_bridge.dart
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

    /** Timeout d'accept() côté GO (attente de connexion du Client). */
    private const val SOCKET_ACCEPT_TIMEOUT_MS = 15_000

    // === JNI ===

    init {
        System.loadLibrary("aegis_core")
    }

    private external fun aegis_wifi_direct_set_fd(fd: Int): Int
    private external fun aegis_wifi_direct_close_fd(): Int

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

    @Volatile
    private var ephemeralName: String? = null

    /** Port d'écoute pré-généré (inclus dans le QR code). */
    @Volatile
    private var ephemeralPort: Int = 0

    @Volatile
    private var eventSink: EventChannel.EventSink? = null

    @Volatile
    private var expectedPeerName: String? = null

    @Volatile
    private var expectedPort: Int = 0

    @Volatile
    private var discoveryActive: Boolean = false

    @Volatile
    private var timeoutHandler: Handler? = null

    @Volatile
    private var timeoutRunnable: Runnable? = null

    /** Executor dédié aux opérations socket (bloquantes, hors main thread). */
    private val socketExecutor = Executors.newSingleThreadExecutor()

    private val secureRandom = SecureRandom()

    // =====================================================================
    // Détection
    // =====================================================================

    fun isSupported(context: Context): Boolean {
        return context.packageManager.hasSystemFeature(
            PackageManager.FEATURE_WIFI_DIRECT
        )
    }

    // =====================================================================
    // Initialisation / Arrêt
    // =====================================================================

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

            // 2. Générer un port d'écoute aléatoire libre
            ephemeralPort = findFreePort()
            Log.i(TAG, "Port éphémère généré: $ephemeralPort")

            // 3. Initialiser WifiP2pManager (main looper obligatoire)
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

    fun shutdown() {
        if (!initialized) return

        cancelDiscoveryTimeout()

        try {
            if (discoveryActive) {
                channel?.let { ch -> manager?.stopPeerDiscovery(ch, null) }
            }
        } catch (t: Throwable) {
            Log.w(TAG, "stopPeerDiscovery a échoué", t)
        }

        try {
            unregisterReceiver()
        } catch (t: Throwable) {
            Log.w(TAG, "unregisterReceiver a échoué", t)
        }

        // Fermer le fd côté Rust (si un socket est ouvert)
        try {
            aegis_wifi_direct_close_fd()
        } catch (t: Throwable) {
            Log.w(TAG, "close_fd a échoué", t)
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
        ephemeralName = null
        ephemeralPort = 0
        expectedPeerName = null
        expectedPort = 0
        discoveryActive = false
        timeoutHandler = null
        timeoutRunnable = null
    }

    // =====================================================================
    // EventChannel
    // =====================================================================

    fun setEventSink(sink: EventChannel.EventSink?) {
        eventSink = sink
        Log.i(TAG, "EventSink ${if (sink == null) "retiré" else "enregistré"}")
    }

    private fun notifyEvent(event: Map<String, Any?>) {
        val sink = eventSink ?: return
        try {
            sink.success(event)
        } catch (t: Throwable) {
            Log.w(TAG, "notifyEvent a échoué", t)
        }
    }

    // =====================================================================
    // BroadcastReceiver
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
                        // No-op
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
                    initiateConnection(filtered.first())
                } else if (peers.isNotEmpty()) {
                    Log.i(TAG, "Aucun peer ne matche le nom éphémère attendu")
                }
            }
        } catch (t: SecurityException) {
            Log.e(TAG, "requestPeers: SecurityException", t)
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
                // La sécurité est assurée par le handshake ed25519 (P0-A.2b.3c)
                // qui suit la connexion Wi-Fi Direct.
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
                    // Ouvrir le socket (bloquant → executor dédié)
                    socketExecutor.execute {
                        openSocket(info)
                    }
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
    // Socket exchange (P0-A.2b.3a)
    // =====================================================================

    /**
     * Ouvre le socket TCP après connexion Wi-Fi Direct.
     *
     * - GO : ouvre ServerSocket(port_A), attend accept()
     * - Client : ouvre Socket(GO_address, port_A)
     *
     * `port_A` = expectedPort (fourni par connectToPeer, issu du QR code).
     *
     * Une fois le socket ouvert, transmet son fd à Rust via JNI.
     */
    private fun openSocket(info: WifiP2pInfo) {
        val port = expectedPort
        if (port <= 0) {
            Log.e(TAG, "openSocket: expectedPort invalide ($port)")
            notifyEvent(mapOf(
                "type" to "socket_error",
                "reason" to "invalid_port",
            ))
            return
        }

        val socket: Socket = try {
            if (info.isGroupOwner) {
                Log.i(TAG, "openSocket: rôle=GO, ServerSocket($port)")
                val server = ServerSocket(port)
                server.soTimeout = SOCKET_ACCEPT_TIMEOUT_MS
                val accepted = server.accept()
                // Fermer le ServerSocket (n'est plus nécessaire)
                try { server.close() } catch (_: Throwable) {}
                accepted
            } else {
                val goAddr = info.groupOwnerAddress?.hostAddress
                    ?: run {
                        Log.e(TAG, "openSocket: groupOwnerAddress null")
                        return
                    }
                Log.i(TAG, "openSocket: rôle=Client, Socket($goAddr:$port)")
                Socket(goAddr, port)
            }
        } catch (t: Throwable) {
            Log.e(TAG, "openSocket: échec ouverture socket", t)
            notifyEvent(mapOf(
                "type" to "socket_error",
                "reason" to (t.message ?: t.javaClass.simpleName),
            ))
            return
        }

        // Transmettre le fd à Rust
        transmitFdToRust(socket)
    }

    /**
     * Détache le fd du Socket et le transmet à Rust via JNI.
     *
     * Après cette fonction, Kotlin ne doit PLUS toucher au Socket
     * (le fd appartient à Rust, qui le fermera au Drop).
     */
    private fun transmitFdToRust(socket: Socket) {
        try {
            val pfd = ParcelFileDescriptor.fromSocket(socket)
            val fd = pfd.detachFd()
            try { pfd.close() } catch (_: Throwable) {}

            // NOTE : on ne ferme PAS le Socket — fermer le Socket fermerait
            // le fd sous-jacent que Rust possède désormais.

            val rc = aegis_wifi_direct_set_fd(fd)
            if (rc != 0) {
                Log.e(TAG, "aegis_wifi_direct_set_fd a échoué: rc=$rc")
                // Le fd n'est pas pris en charge par Rust → on le ferme
                try { socket.close() } catch (_: Throwable) {}
                notifyEvent(mapOf(
                    "type" to "socket_error",
                    "reason" to "fd_rejected_by_rust",
                    "code" to rc,
                ))
                return
            }

            Log.i(TAG, "Socket fd transmis à Rust (fd=$fd)")
            notifyEvent(mapOf(
                "type" to "socket_ready",
                "role" to if (expectedPort > 0) "go_or_client" else "unknown",
            ))
        } catch (t: Throwable) {
            Log.e(TAG, "transmitFdToRust a échoué", t)
            try { socket.close() } catch (_: Throwable) {}
            notifyEvent(mapOf(
                "type" to "socket_error",
                "reason" to (t.message ?: t.javaClass.simpleName),
            ))
        }
    }

    // =====================================================================
    // API publique (exposée à Flutter via MethodChannel)
    // =====================================================================

    fun getState(): Map<String, Any> {
        val ctx = appContext
        return mapOf(
            "supported" to (ctx?.let { isSupported(it) } ?: false),
            "initialized" to initialized,
            "wifi_p2p_enabled" to (manager != null && channel != null),
            "discovery_active" to discoveryActive,
        )
    }

    fun getEphemeralName(): String? = ephemeralName

    fun getEphemeralPort(): Int = ephemeralPort

    /**
     * Lance une découverte ciblée.
     */
    @SuppressLint("MissingPermission")
    fun startDiscovery(expectedName: String?): Int {
        if (!initialized) {
            Log.w(TAG, "startDiscovery: bridge non initialisé")
            return -1
        }

        val mgr = manager ?: return -1
        val ch = channel ?: return -1

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
     * `deviceName`   : nom éphémère 12 chars fourni par le QR code.
     * `peerPort`     : port d'écoute du peer (inclus dans son QR).
     *
     * Retour :
     *   0  = discovery lancée
     *  -1  = bridge non initialisé
     *  -2  = deviceName vide
     *  -3  = peerPort invalide (<= 0 ou > 65535)
     *  -4  = discovery déjà active
     *  -5  = SecurityException
     *  -6  = échec framework
     */
    fun connectToPeer(deviceName: String, peerPort: Int): Int {
        if (!initialized) return -1
        if (deviceName.isEmpty()) return -2
        if (peerPort <= 0 || peerPort > 65535) return -3

        expectedPort = peerPort
        return startDiscovery(deviceName)
    }

    /**
     * Déconnecte du peer actif et stoppe la discovery.
     */
    @SuppressLint("MissingPermission")
    fun disconnect(): Int {
        if (!initialized) return -1

        val mgr = manager ?: return -1
        val ch = channel ?: return -1

        cancelDiscoveryTimeout()
        expectedPeerName = null
        expectedPort = 0

        // Fermer le fd côté Rust
        try {
            aegis_wifi_direct_close_fd()
        } catch (t: Throwable) {
            Log.w(TAG, "close_fd a échoué", t)
        }

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

    private fun generateEphemeralName(): String {
        val sb = StringBuilder(EPHEMERAL_NAME_LENGTH)
        repeat(EPHEMERAL_NAME_LENGTH) {
            sb.append(BASE62[secureRandom.nextInt(BASE62.length)])
        }
        return sb.toString()
    }

    /** Trouve un port TCP libre en demandant au noyau. */
    private fun findFreePort(): Int {
        return try {
            ServerSocket(0).use { it.localPort }
        } catch (t: Throwable) {
            // Fallback : port aléatoire dans la plage dynamique
            Log.w(TAG, "findFreePort a échoué, fallback aléatoire", t)
            49152 + secureRandom.nextInt(16384)
        }
    }

    private fun scheduleDiscoveryTimeout() {
        cancelDiscoveryTimeout()
        val handler = timeoutHandler ?: return

        val r = Runnable {
            Log.w(TAG, "Discovery timeout (${DISCOVERY_TIMEOUT_MS / 1000}s)")
            notifyEvent(mapOf("type" to "discovery_timeout"))
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

    private fun cancelDiscoveryTimeout() {
        val handler = timeoutHandler ?: return
        val r = timeoutRunnable ?: return
        handler.removeCallbacks(r)
        timeoutRunnable = null
    }
}