package com.example.aegis_app

import android.content.Context
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel

class BleMeshBridge(
    private val context: Context,
    messenger: BinaryMessenger
) {
    private val methodChannel = MethodChannel(messenger, "com.aegis/ble_mesh")
    private val eventChannel = EventChannel(messenger, "com.aegis/ble_mesh_events")

    private var eventSink: EventChannel.EventSink? = null

    init {
        methodChannel.setMethodCallHandler { call, result ->
            when (call.method) {
                "initialize" -> {
                    // TODO P0-A.3b : Initialiser BluetoothAdapter, GattServer, Advertiser
                    result.success(true)
                }
                "startMesh" -> {
                    // TODO P0-A.3b : Démarrer advertising + scanning + GATT server
                    result.success(true)
                }
                "stopMesh" -> {
                    // TODO P0-A.3b : Arrêter advertising + scanning + GATT server
                    result.success(true)
                }
                "isSupported" -> {
                    // TODO : Vérifier si BLE est supporté par le hardware
                    result.success(true)
                }
                else -> result.notImplemented()
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

    fun destroy() {
        methodChannel.setMethodCallHandler(null)
        eventChannel.setStreamHandler(null)
        eventSink = null
    }
}