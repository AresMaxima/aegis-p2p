package com.example.aegis_app

import android.Manifest
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.ParcelUuid
import android.util.Base64
import android.util.Log
import androidx.core.content.ContextCompat
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/**
 * P0-A.3b (2026-10-11) — BLE Mesh bridge Kotlin.
 * P0-A.3c.2 (2026-10-12) — JNI pipes vers Rust.
 * P0-A.3d.3b (2026-10-14) — Integration reader thread Rust + framing D86/D88.
 * P0-A.3e.2b.2 (2026-10-17) — Handshake ed25519 (dispatch 0x03 + API Dart).
 *
 * Advertising (Q2) : LOW_LATENCY (100 ms) → LOW_POWER (1000 ms) après 30 s.
 * TX power (D77)   : ULTRA_LOW (~1 m).
 * Device name      : non inclus (D77).
 * UUIDs (D77)      : v4 aléatoires, hardcodés.
 *
 * GATT server : 1 service, 2 caractéristiques (WRITE + NOTIFY avec CCCD).
 * Pipes JNI    : 2 pipes POSIX (in / out) vers Rust (ble_mesh.rs).
 *
 * Framing :
 *   Entrant (Kotlin → Rust) : [u32 BE length][fragment bytes]        (D88)
 *   Sortant (Rust → Kotlin) : [u8 type][u32 BE len][bytes]           (D86)
 *     type 0x01 = forward au peer via GATT NOTIFY
 *     type 0x02 = delivery locale → EventChannel Dart
 *     type 0x03 = événement handshake → EventChannel Dart (P0-A.3e.2b.2)
 */
class BleMeshBridge(
    private val context: Context,
    messenger: BinaryMessenger
) {

    companion object {
        private const val TAG = "AEGIS_BLE"

        private const val METHOD_CHANNEL_NAME = "com.aegis/ble_mesh"
        private const val EVENT_CHANNEL_NAME  = "com.aegis/ble_mesh_events"

        // ─────────────────────────────────────────────────────────────
        // D77 — UUIDs v4 aléatoires (aucun pattern identifiable).
        // ─────────────────────────────────────────────────────────────
        val UUID_SERVICE: UUID    = UUID.fromString("8f2a4c1e-9d3b-4a7f-b6e5-1c8d0e2f3a5b")
        val UUID_CHAR_WRITE: UUID = UUID.fromString("8f2a4c1e-9d3b-4a7f-b6e5-1c8d0e2f3a5c")
        val UUID_CHAR_NOTIFY: UUID= UUID.fromString("8f2a4c1e-9d3b-4a7f-b6e5-1c8d0e2f3a5d")

        // CCCD (Client Characteristic Configuration Descriptor) — SIG standard.
        val UUID_CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        // Q2 — Advertising adaptatif.
        private const val ADVERTISE_ADAPTIVE_DELAY_MS = 30_000L

        // D86 — Bornes de sécurité du framing sortant.
        private const val MAX_FRAME_SIZE = 64 * 1024
    }

    // ── État interne ──────────────────────────────────────────────────
    private val handler = Handler(Looper.getMainLooper())
    private var eventSink: EventChannel.EventSink? = null

    private val methodChannel: MethodChannel
    private val eventChannel: EventChannel

    private var advertiser: BluetoothLeAdvertiser? = null
    private var gattServer: BluetoothGattServer? = null
    private var advertisingActive = false
    private var meshActive = false
    private var connectedDevice: BluetoothDevice? = null

    // ── P0-A.3c.2 : pipes JNI ────────────────────────────────────────
    //
    // pipeIn  : Kotlin écrit  → Rust lit   (GATT WRITE reçu du peer)
    // pipeOut : Kotlin lit    ← Rust écrit (GATT NOTIFY vers le peer)
    //
    // C59 : createPipe() retourne un Array<ParcelFileDescriptor>
    //       (2 éléments), pas un objet unique.
    //
    private var pipeIn: Array<ParcelFileDescriptor>? = null   // [readEnd, writeEnd]
    private var pipeOut: Array<ParcelFileDescriptor>? = null  // [readEnd, writeEnd]

    private var writerThread: Thread? = null
    private val writerRunning = AtomicBoolean(false)

    // ── Externals JNI (résolus au nom de MainActivity) ───────────────
    private val mainActivity get() = context as? MainActivity

    init {
        methodChannel = MethodChannel(messenger, METHOD_CHANNEL_NAME)
        eventChannel  = EventChannel(messenger, EVENT_CHANNEL_NAME)

        methodChannel.setMethodCallHandler { call, result ->
            try {
                when (call.method) {
                    "isSupported"    -> result.success(actionIsSupported())
                    "initialize"     -> result.success(actionInitialize())
                    "startMesh"      -> result.success(actionStartMesh())
                    "stopMesh"       -> result.success(actionStopMesh())
                    // P0-A.3e.2b.2 : handshake ed25519 sur BLE
                    "startHandshake" -> {
                        val fpB64 = call.argument<String>("peerFingerprintB64") ?: ""
                        val isInitiator = call.argument<Boolean>("isInitiator") ?: false
                        result.success(actionStartHandshake(fpB64, isInitiator))
                    }
                    "handshakeIsComplete" -> {
                        result.success(actionHandshakeIsComplete())
                    }
                    "handshakeReset" -> {
                        result.success(actionHandshakeReset())
                    }
                    else -> result.notImplemented()
                }
            } catch (t: Throwable) {
                Log.e(TAG, "MethodCall '${call.method}' a échoué", t)
                result.error("BLE_ERROR", t.message ?: "unknown", null)
            }
        }

        eventChannel.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                eventSink = events
            }
            override fun onCancel(arguments: Any?) {
                eventSink = null
            }
        })
    }

    // =================================================================
    // Actions exposées au Dart
    // =================================================================

    private fun actionIsSupported(): Boolean {
        return try {
            if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)) {
                return false
            }
            val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
            manager?.adapter != null
        } catch (t: Throwable) {
            Log.e(TAG, "isSupported a échoué", t)
            false
        }
    }

    private fun actionInitialize(): Boolean {
        if (!actionIsSupported()) {
            Log.w(TAG, "BLE non supporté par ce device")
            return false
        }
        if (!hasConnectPermission()) {
            Log.w(TAG, "initialize: BLUETOOTH_CONNECT manquant")
            return false
        }

        return try {
            val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
            val adapter = manager.adapter ?: return false
            if (!adapter.isEnabled) {
                Log.w(TAG, "initialize: Bluetooth désactivé")
                return false
            }
            advertiser = adapter.bluetoothLeAdvertiser
            if (advertiser == null) {
                Log.w(TAG, "initialize: BluetoothLeAdvertiser indisponible")
                return false
            }
            Log.i(TAG, "initialize OK (BLE disponible)")
            true
        } catch (t: Throwable) {
            Log.e(TAG, "initialize a échoué", t)
            false
        }
    }

    private fun actionStartMesh(): Boolean {
        if (meshActive) {
            Log.w(TAG, "startMesh: déjà actif")
            return true
        }
        if (!hasAdvertisePermission() || !hasConnectPermission()) {
            Log.w(TAG, "startMesh: permissions BLE manquantes")
            return false
        }
        if (advertiser == null) {
            if (!actionInitialize()) return false
        }

        return try {
            setupGattServer()
            setupPipes()          // P0-A.3c.2 + P0-A.3d.3b
            startAdvertisingLowLatency()
            meshActive = true
            emitEvent(mapOf("type" to "mesh_started"))
            Log.i(TAG, "startMesh OK (avec pipes JNI)")
            true
        } catch (t: Throwable) {
            Log.e(TAG, "startMesh a échoué", t)
            teardownPipes()       // cleanup partiel
            teardownGattServer()
            emitEvent(mapOf("type" to "mesh_start_failed", "error" to (t.message ?: "unknown")))
            false
        }
    }

    private fun actionStopMesh(): Boolean {
        if (!meshActive) return true
        return try {
            stopAdvertising()
            teardownPipes()       // AVANT teardownGattServer (sinon notify de fd fermé)
            teardownGattServer()
            meshActive = false
            emitEvent(mapOf("type" to "mesh_stopped"))
            Log.i(TAG, "stopMesh OK")
            true
        } catch (t: Throwable) {
            Log.e(TAG, "stopMesh a échoué", t)
            false
        }
    }

    // =================================================================
    // P0-A.3e.2b.2 — Handshake ed25519 sur BLE
    // =================================================================

    /**
     * Démarre un handshake ed25519 sur BLE.
     *
     * @param peerFingerprintB64  Fingerprint SHA-256 de la pubkey ed25519 du
     *                            peer, encodé en Base64 (32 octets bruts).
     * @param isInitiator         true = client GATT (envoie Msg1).
     *                            false = serveur GATT (attend Msg1).
     * @return true si démarré, false sinon.
     */
    private fun actionStartHandshake(peerFingerprintB64: String, isInitiator: Boolean): Boolean {
        if (!meshActive) {
            Log.w(TAG, "startHandshake: mesh pas actif")
            return false
        }

        val fp = try {
            Base64.decode(peerFingerprintB64, Base64.NO_WRAP)
        } catch (t: Throwable) {
            Log.e(TAG, "startHandshake: Base64 decode a échoué", t)
            return false
        }
        if (fp.size != 32) {
            Log.e(TAG, "startHandshake: fingerprint invalide (${fp.size} octets, attendu 32)")
            return false
        }

        val rc = if (isInitiator) {
            mainActivity?.aegis_ble_handshake_start_initiator(fp)
        } else {
            mainActivity?.aegis_ble_handshake_start_responder(fp)
        } ?: -1

        if (rc != 0) {
            Log.e(TAG, "startHandshake a échoué: rc=$rc (isInitiator=$isInitiator)")
            emitEvent(mapOf("type" to "handshake_event", "status" to "failed:$rc"))
            return false
        }

        Log.i(TAG, "Handshake démarré (role=${if (isInitiator) "initiator" else "responder"})")
        return true
    }

    /**
     * Retourne true si le handshake ed25519 est terminé avec succès.
     */
    private fun actionHandshakeIsComplete(): Boolean {
        return (mainActivity?.aegis_ble_handshake_is_complete() ?: 0) == 1
    }

    /**
     * Réinitialise l'état handshake (à appeler sur déconnexion).
     */
    private fun actionHandshakeReset(): Boolean {
        val rc = mainActivity?.aegis_ble_handshake_reset() ?: -1
        return rc == 0
    }

    // =================================================================
    // P0-A.3c.2 — Pipes JNI vers Rust
    // =================================================================

    private fun setupPipes() {
        // createPipe() retourne [readEnd, writeEnd].
        //
        // pipeIn : Kotlin ÉCRIT (writeEnd), Rust LIT (readEnd).
        //          → pipeIn[0] = readEnd → détaché vers Rust
        //          → pipeIn[1] = writeEnd → gardé par Kotlin
        //
        // pipeOut : Rust ÉCRIT (writeEnd), Kotlin LIT (readEnd).
        //          → pipeOut[0] = readEnd → gardé par Kotlin
        //          → pipeOut[1] = writeEnd → détaché vers Rust
        //
        pipeIn  = ParcelFileDescriptor.createPipe()
        pipeOut = ParcelFileDescriptor.createPipe()

        val pIn = pipeIn ?: throw IllegalStateException("createPipe in a retourné null")
        val pOut = pipeOut ?: throw IllegalStateException("createPipe out a retourné null")

        // Détacher les fd qui partent vers Rust (C56 : transfert de propriété).
        val rustReadInFd  = pIn[0].detachFd()   // Rust lit depuis pipeIn
        val rustWriteOutFd = pOut[1].detachFd() // Rust écrit dans pipeOut

        // C56 : refuser fd <= 0 côté Rust. Vérification préventive Kotlin.
        if (rustReadInFd <= 0 || rustWriteOutFd <= 0) {
            throw IllegalStateException(
                "detachFd a retourné fd invalide (in=$rustReadInFd, out=$rustWriteOutFd)"
            )
        }

        // Appel JNI → Rust enregistre les fd.
        val rc = mainActivity?.aegis_ble_mesh_set_pipes(rustReadInFd, rustWriteOutFd) ?: -1
        if (rc != 0) {
            throw IllegalStateException("aegis_ble_mesh_set_pipes a échoué: rc=$rc")
        }

        // P0-A.3d.3b : démarrer le reader thread Rust sur les MÊMES fd.
        // Le reader prend ownership côté Rust (File::from_raw_fd sur in_fd).
        // Les fd rustReadInFd et rustWriteOutFd ont déjà été détachés par
        // set_pipes (C56) — on les passe tels quels, SANS re-détacher.
        val rcReader = mainActivity?.aegis_ble_mesh_reader_start(rustReadInFd, rustWriteOutFd) ?: -1
        if (rcReader != 0) {
            throw IllegalStateException("aegis_ble_mesh_reader_start a échoué: rc=$rcReader")
        }

        // Démarrer le thread writer Kotlin (Rust → Kotlin → GATT NOTIFY).
        startWriterThread()

        Log.i(TAG, "Pipes JNI configurés (in=$rustReadInFd, out=$rustWriteOutFd)")
        emitEvent(mapOf("type" to "pipes_ready"))
    }

    private fun teardownPipes() {
        // Arrêter le thread reader AVANT de fermer les fd.
        writerRunning.set(false)
        try {
            writerThread?.interrupt()
            writerThread?.join(1000)
        } catch (_: Throwable) {}
        writerThread = null

        // P0-A.3d.3b : arrêter le reader Rust AVANT shutdown.
        // reader_stop join le thread ; File::from_raw_fd(in_fd) drop → close.
        try {
            mainActivity?.aegis_ble_mesh_reader_stop()
        } catch (t: Throwable) {
            Log.e(TAG, "aegis_ble_mesh_reader_stop a échoué", t)
        }

        // Signaler à Rust qu'on ferme (set_pipes/shutdown — P0-A.3c.1).
        try {
            mainActivity?.aegis_ble_mesh_shutdown()
        } catch (t: Throwable) {
            Log.e(TAG, "aegis_ble_mesh_shutdown a échoué", t)
        }

        // Fermer les extrémités restantes côté Kotlin.
        // Note : les fd détachés (rustReadInFd, rustWriteOutFd) sont
        // possédés par Rust — c'est lui qui les fermera.
        try {
            pipeIn?.get(1)?.close()   // writeEnd Kotlin
        } catch (_: Throwable) {}
        try {
            pipeOut?.get(0)?.close()  // readEnd Kotlin
        } catch (_: Throwable) {}
        pipeIn = null
        pipeOut = null

        Log.i(TAG, "Pipes JNI fermés")
    }

    private fun startWriterThread() {
        val readEnd = pipeOut?.get(0) ?: run {
            Log.e(TAG, "startWriterThread: pipeOut readEnd manquant")
            return
        }

        writerRunning.set(true)
        writerThread = Thread({
            Log.i(TAG, "Writer thread démarré")
            val input = FileInputStream(readEnd.fileDescriptor)
            try {
                while (writerRunning.get() && !Thread.currentThread().isInterrupted) {
                    // D86 : framing sortant [u8 type][u32 BE len][bytes].
                    // Rust écrit ce préfixe pour chaque message.
                    val header = readExactly(input, 5) ?: break
                    val type = header[0].toInt() and 0xFF
                    val len = ((header[1].toInt() and 0xFF) shl 24) or
                              ((header[2].toInt() and 0xFF) shl 16) or
                              ((header[3].toInt() and 0xFF) shl 8) or
                              (header[4].toInt() and 0xFF)

                    // Borne de sécurité : refuse les frames > 64 KB (défense DoS).
                    if (len < 0 || len > MAX_FRAME_SIZE) {
                        Log.e(TAG, "Writer: len invalide $len (drop + break)")
                        break
                    }

                    val payload = if (len > 0) {
                        readExactly(input, len) ?: break
                    } else {
                        ByteArray(0)
                    }

                    when (type) {
                        0x01 -> notifyPeer(payload)         // forward au peer
                        0x02 -> emitLocalDelivery(payload)  // delivery locale
                        0x03 -> emitHandshakeEvent(payload) // P0-A.3e.2b.2 handshake event
                        else -> Log.w(TAG, "Writer: type inconnu 0x${type.toString(16)}")
                    }
                }
            } catch (t: Throwable) {
                if (writerRunning.get()) {
                    Log.e(TAG, "Writer thread interrompu", t)
                }
            } finally {
                try { input.close() } catch (_: Throwable) {}
                Log.i(TAG, "Writer thread arrêté")
            }
        }, "AegisBleMeshWriter").apply {
            isDaemon = true
            start()
        }
    }

    /**
     * Lit exactement `n` octets depuis `input`.
     *
     * FileInputStream.read() peut retourner moins que demandé (comportement
     * POSIX read(2)). On boucle jusqu'à avoir les n octets ou EOF.
     *
     * Retourne `null` si EOF avant d'avoir lu n octets.
     */
    private fun readExactly(input: FileInputStream, n: Int): ByteArray? {
        if (n <= 0) return ByteArray(0)
        val out = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = input.read(out, off, n - off)
            if (r < 0) return null  // EOF
            off += r
        }
        return out
    }

    /**
     * D86 (Q15) : delivery locale → EventChannel Flutter.
     *
     * Le payload est encodé en Base64 pour traverser le canal Dart
     * (StandardMessageCodec ne supporte pas ByteArray directement).
     *
     * Le flag NO_WRAP évite les \n tous les 76 caractères (padding Base64).
     */
    private fun emitLocalDelivery(payload: ByteArray) {
        val b64 = Base64.encodeToString(payload, Base64.NO_WRAP)
        emitEvent(mapOf("type" to "local_delivery", "payload_b64" to b64))
    }

    /**
     * P0-A.3e.2b.2 (D86 type 0x03) : événement handshake → EventChannel Dart.
     *
     * Payload ASCII :
     *   - "complete"        → handshake terminé, session prête
     *   - "failed:<code>"   → échec (code HandshakeError::to_code)
     *
     * Format event :
     *   {type: "handshake_event", status: "complete" | "failed:-50" | ...}
     */
    private fun emitHandshakeEvent(payload: ByteArray) {
        val status = try {
            String(payload, Charsets.UTF_8)
        } catch (t: Throwable) {
            Log.e(TAG, "emitHandshakeEvent: payload non-UTF8", t)
            "failed:-1"
        }
        emitEvent(mapOf("type" to "handshake_event", "status" to status))
    }

    private fun notifyPeer(data: ByteArray) {
        val dev = connectedDevice ?: run {
            // Pas de peer connecté → drop silencieux (le buffer Rust
            // accumule en attendant — voir P0-A.3d).
            return
        }
        val server = gattServer ?: return
        val service = server.getService(UUID_SERVICE) ?: return
        val notifyChar = service.getCharacteristic(UUID_CHAR_NOTIFY) ?: return

        try {
            notifyChar.value = data
            val ok = server.notifyCharacteristicChanged(dev, notifyChar, false)
            if (!ok) {
                Log.w(TAG, "notifyCharacteristicChanged a retourné false")
            }
        } catch (t: Throwable) {
            Log.e(TAG, "notifyPeer a échoué", t)
        }
    }

    /**
     * Écrit un fragment reçu via GATT WRITE dans pipeIn (Kotlin → Rust).
     * Appelée depuis onCharacteristicWriteRequest.
     */
    private fun forwardToRust(data: ByteArray) {
        val writeEnd = pipeIn?.get(1) ?: return
        try {
            val out = FileOutputStream(writeEnd.fileDescriptor)
            // D88 : framing entrant [u32 BE length][fragment bytes].
            // Rust reader_loop attend ce préfixe pour délimiter les fragments
            // (pipe POSIX = stream d'octets, pas de notion de messages).
            val lenPrefix = byteArrayOf(
                (data.size ushr 24).toByte(),
                (data.size ushr 16).toByte(),
                (data.size ushr 8).toByte(),
                data.size.toByte(),
            )
            out.write(lenPrefix)
            out.write(data)
            out.flush()
        } catch (t: Throwable) {
            Log.e(TAG, "forwardToRust a échoué (${data.size} octets)", t)
        }
    }

    // =================================================================
    // Advertising (Q2 + D77)
    // =================================================================

    private fun startAdvertisingLowLatency() {
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_ULTRA_LOW)
            .setConnectable(true)
            .setTimeout(0)
            .build()

        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)      // D77 — pas de nom
            .setIncludeTxPowerLevel(false)    // pas de fuite de TX power
            .addServiceUuid(ParcelUuid(UUID_SERVICE))
            .build()

        advertiser?.startAdvertising(settings, data, advertiseCallback)
        advertisingActive = true

        handler.postDelayed({
            if (advertisingActive) switchToLowPowerAdvertising()
        }, ADVERTISE_ADAPTIVE_DELAY_MS)
    }

    private fun switchToLowPowerAdvertising() {
        try {
            advertiser?.stopAdvertising(advertiseCallback)
        } catch (_: Throwable) {}

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_POWER)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_ULTRA_LOW)
            .setConnectable(true)
            .setTimeout(0)
            .build()

        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .addServiceUuid(ParcelUuid(UUID_SERVICE))
            .build()

        try {
            advertiser?.startAdvertising(settings, data, advertiseCallback)
            Log.i(TAG, "Advertising basculé en LOW_POWER (30 s écoulées)")
        } catch (t: Throwable) {
            Log.e(TAG, "switchToLowPowerAdvertising a échoué", t)
        }
    }

    private fun stopAdvertising() {
        advertisingActive = false
        handler.removeCallbacksAndMessages(null)
        try {
            advertiser?.stopAdvertising(advertiseCallback)
        } catch (t: Throwable) {
            Log.e(TAG, "stopAdvertising a échoué", t)
        }
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            Log.i(TAG, "Advertising démarré (mode=${settingsInEffect?.mode})")
            emitEvent(mapOf("type" to "advertising_started"))
        }
        override fun onStartFailure(errorCode: Int) {
            Log.e(TAG, "Advertising échoué (code=$errorCode)")
            emitEvent(mapOf("type" to "advertising_failed", "errorCode" to errorCode))
        }
    }

    // =================================================================
    // GATT server
    // =================================================================

    private fun setupGattServer() {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        gattServer = manager.openGattServer(context, gattServerCallback)
            ?: throw IllegalStateException("openGattServer a retourné null")

        val service = BluetoothGattService(
            UUID_SERVICE,
            BluetoothGattService.SERVICE_TYPE_PRIMARY
        )

        val charWrite = BluetoothGattCharacteristic(
            UUID_CHAR_WRITE,
            BluetoothGattCharacteristic.PROPERTY_WRITE or
                BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        service.addCharacteristic(charWrite)

        val charNotify = BluetoothGattCharacteristic(
            UUID_CHAR_NOTIFY,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY or
                BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ
        )
        val cccd = BluetoothGattDescriptor(
            UUID_CCCD,
            BluetoothGattDescriptor.PERMISSION_READ or
                BluetoothGattDescriptor.PERMISSION_WRITE
        )
        charNotify.addDescriptor(cccd)
        service.addCharacteristic(charNotify)

        val ok = gattServer?.addService(service) ?: false
        if (!ok) throw IllegalStateException("addService a échoué")

        Log.i(TAG, "GATT server prêt (service + 2 chars)")
    }

    private fun teardownGattServer() {
        try {
            gattServer?.close()
        } catch (t: Throwable) {
            Log.e(TAG, "teardownGattServer a échoué", t)
        } finally {
            gattServer = null
            connectedDevice = null
        }
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice?, status: Int, newState: Int) {
            super.onConnectionStateChange(device, status, newState)
            val addr = device?.address ?: "unknown"
            when (newState) {
                android.bluetooth.BluetoothProfile.STATE_CONNECTED -> {
                    connectedDevice = device
                    Log.i(TAG, "Peer connecté: $addr")
                    emitEvent(mapOf("type" to "device_connected", "address" to addr))
                }
                android.bluetooth.BluetoothProfile.STATE_DISCONNECTED -> {
                    if (connectedDevice?.address == addr) connectedDevice = null
                    Log.i(TAG, "Peer déconnecté: $addr")
                    emitEvent(mapOf("type" to "device_disconnected", "address" to addr))
                }
            }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice?,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic?,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            super.onCharacteristicWriteRequest(
                device, requestId, characteristic, preparedWrite, responseNeeded, offset, value
            )

            if (characteristic?.uuid == UUID_CHAR_WRITE && value != null) {
                // P0-A.3c.2 + P0-A.3d.3b : pipe vers Rust avec framing D88.
                forwardToRust(value)
                Log.d(TAG, "WRITE reçu: ${value.size} octets → pipe Rust")
            }

            if (responseNeeded) {
                try {
                    gattServer?.sendResponse(
                        device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null
                    )
                } catch (t: Throwable) {
                    Log.e(TAG, "sendResponse a échoué", t)
                }
            }
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice?,
            requestId: Int,
            descriptor: BluetoothGattDescriptor?,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            super.onDescriptorWriteRequest(
                device, requestId, descriptor, preparedWrite, responseNeeded, offset, value
            )
            val enabled = value?.contentEquals(
                BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            ) == true
            if (descriptor?.uuid == UUID_CCCD) {
                Log.i(TAG, "CCCD update: notify=$enabled")
                emitEvent(mapOf("type" to "cccd_changed", "enabled" to enabled))
            }
            if (responseNeeded) {
                try {
                    gattServer?.sendResponse(
                        device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null
                    )
                } catch (t: Throwable) {
                    Log.e(TAG, "sendResponse CCCD a échoué", t)
                }
            }
        }
    }

    // =================================================================
    // Permissions runtime (API 31+)
    // =================================================================

    private fun hasAdvertisePermission(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return true
        return ContextCompat.checkSelfPermission(
            context, Manifest.permission.BLUETOOTH_ADVERTISE
        ) == PackageManager.PERMISSION_GRANTED
    }

    private fun hasConnectPermission(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return true
        return ContextCompat.checkSelfPermission(
            context, Manifest.permission.BLUETOOTH_CONNECT
        ) == PackageManager.PERMISSION_GRANTED
    }

    // =================================================================
    // Émission d'événements vers Flutter
    // =================================================================

    private fun emitEvent(payload: Map<String, Any?>) {
        val sink = eventSink ?: return
        handler.post { sink.success(payload) }
    }

    // =================================================================
    // Cleanup
    // =================================================================

    fun destroy() {
        try { stopAdvertising() } catch (_: Throwable) {}
        try { teardownPipes() } catch (_: Throwable) {}    // AVANT teardownGattServer
        try { teardownGattServer() } catch (_: Throwable) {}
        handler.removeCallbacksAndMessages(null)
        methodChannel.setMethodCallHandler(null)
        eventChannel.setStreamHandler(null)
        eventSink = null
        meshActive = false
    }
}