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
import android.os.ParcelUuid
import android.util.Log
import androidx.core.content.ContextCompat
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import java.util.UUID

/**
 * P0-A.3b (2026-10-11) — BLE Mesh bridge Kotlin.
 *
 * Advertising (Q2) : LOW_LATENCY (100 ms) → LOW_POWER (1000 ms) après 30 s.
 * TX power (D77)   : ULTRA_LOW (~1 m).
 * Device name      : non inclus (D77).
 * UUIDs (D77)      : v4 aléatoires, hardcodés.
 *
 * GATT server : 1 service, 2 caractéristiques (WRITE + NOTIFY avec CCCD).
 * Le pipeline Rust (P0-A.3c/d) consommera les données via JNI pipes.
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
        // Obligatoire pour qu'un client puisse activer NOTIFY.
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
            startAdvertisingLowLatency()
            meshActive = true
            emitEvent(mapOf("type" to "mesh_started"))
            Log.i(TAG, "startMesh OK")
            true
        } catch (t: Throwable) {
            Log.e(TAG, "startMesh a échoué", t)
            emitEvent(mapOf("type" to "mesh_start_failed", "error" to (t.message ?: "unknown")))
            false
        }
    }

    private fun actionStopMesh(): Boolean {
        if (!meshActive) return true
        return try {
            stopAdvertising()
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

        // Bascule vers LOW_POWER après 30 s (Q2).
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
        if (gattServer == null) {
            throw IllegalStateException("openGattServer a retourné null")
        }

        val service = BluetoothGattService(
            UUID_SERVICE,
            BluetoothGattService.SERVICE_TYPE_PRIMARY
        )

        // Char WRITE (RX fragments depuis le peer).
        val charWrite = BluetoothGattCharacteristic(
            UUID_CHAR_WRITE,
            BluetoothGattCharacteristic.PROPERTY_WRITE or
                BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        service.addCharacteristic(charWrite)

        // Char NOTIFY (TX fragments vers le peer).
        val charNotify = BluetoothGattCharacteristic(
            UUID_CHAR_NOTIFY,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY or
                BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ
        )
        // CCCD obligatoire pour permettre au client de souscrire.
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
            // P0-A.3c : sera redirigé vers Rust via JNI pipe.
            Log.d(TAG, "WRITE reçu: ${value?.size ?: 0} octets (offset=$offset)")

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
            // CCCD write = activation/désactivation NOTIFY.
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
        try { teardownGattServer() } catch (_: Throwable) {}
        handler.removeCallbacksAndMessages(null)
        methodChannel.setMethodCallHandler(null)
        eventChannel.setStreamHandler(null)
        eventSink = null
        meshActive = false
    }
}