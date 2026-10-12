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
 *
 * Advertising (Q2) : LOW_LATENCY (100 ms) → LOW_POWER (1000 ms) après 30 s.
 * TX power (D77)   : ULTRA_LOW (~1 m).
 * Device name      : non inclus (D77).
 * UUIDs (D77)      : v4 aléatoires, hardcodés.
 *
 * GATT server : 1 service, 2 caractéristiques (WRITE + NOTIFY avec CCCD).
 * Pipes JNI    : 2 pipes POSIX (in / out) vers Rust (ble_mesh.rs).
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
                    "isSupported" -> result.success(actionIsSupported())
                    "initialize"  -> result.success(actionInitialize())
                    "startMesh"   -> result.success(actionStartMesh())
                    "stopMesh"    -> result.success(actionStopMesh())
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
            setupPipes()          // P0-A.3c.2
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

        // Démarrer le thread reader (Rust → Kotlin → GATT NOTIFY).
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

        // Signaler à Rust qu'on ferme.
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
            val buffer = ByteArray(244)  // Q3 : max fragment size (MTU-3 plafonné à 244)
            try {
                while (writerRunning.get() && !Thread.currentThread().isInterrupted) {
                    val n = input.read(buffer)
                    if (n <= 0) {
                        if (n < 0) break  // EOF
                        continue
                    }
                    val chunk = buffer.copyOf(n)
                    notifyPeer(chunk)
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
                // P0-A.3c.2 : pipe vers Rust.
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