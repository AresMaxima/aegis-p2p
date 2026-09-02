package com.example.aegis_app

import android.content.Context
import android.view.Surface
import android.view.SurfaceHolder
import android.view.SurfaceView
import io.flutter.plugin.platform.PlatformView

class BlindView(context: Context, id: Int, creationParams: Map<String?, Any?>?) : PlatformView, SurfaceHolder.Callback {
    private val surfaceView: SurfaceView = SurfaceView(context)

    init {
        surfaceView.holder.addCallback(this)
    }

    override fun getView() = surfaceView
    override fun dispose() {}

    override fun surfaceCreated(holder: SurfaceHolder) {
        bindSurfaceToNative(holder.surface)
    }
    
    override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {}
    override fun surfaceDestroyed(holder: SurfaceHolder) {}

    // Appel JNI vers C++
    external fun bindSurfaceToNative(surface: Surface)

    companion object {
        init { System.loadLibrary("aegis_jni") }
    }
}