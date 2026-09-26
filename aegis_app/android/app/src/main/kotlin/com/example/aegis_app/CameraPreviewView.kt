package com.example.aegis_app

import android.content.Context
import android.util.Log
import android.view.View
import androidx.camera.view.PreviewView
import io.flutter.plugin.platform.PlatformView

/**
 * PlatformView Flutter qui expose un PreviewView CameraX pour l'aperçu live.
 *
 * Cycle :
 *   1. Flutter monte AndroidView('com.aegis.p2p/camera_preview')
 *   2. Cette classe est instanciée et s'auto-enregistre auprès de MainActivity
 *      via `MainActivity.attachPreviewView(previewView)`.
 *   3. MainActivity lie CameraX `Preview` à ce PreviewView → aperçu LIVE.
 *
 * FLAG_SECURE est hérité globalement de MainActivity (activé dans main.dart).
 */
class CameraPreviewView(context: Context, id: Int) : PlatformView {

    companion object {
        private const val TAG = "AEGIS_CameraPreview"
    }

    private val previewView: PreviewView = PreviewView(context).apply {
        // FILL_CENTER garde le ratio et remplit tout l'espace Flutter.
        scaleType = PreviewView.ScaleType.FILL_CENTER
        implementationMode = PreviewView.ImplementationMode.COMPATIBLE
    }

    init {
        MainActivity.attachPreviewView(previewView)
        Log.i(TAG, "PreviewView enregistrée (id=$id)")
    }

    override fun getView(): View = previewView

    override fun dispose() {
        MainActivity.detachPreviewView(previewView)
        Log.i(TAG, "PreviewView disposée")
    }
}