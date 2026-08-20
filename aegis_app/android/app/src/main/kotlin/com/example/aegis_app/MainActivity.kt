package com.example.aegis_app // Garde ton nom de package exact si différent

import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine

class MainActivity: FlutterActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        // BLOCAGE MATÉRIEL BLINDÉ ANTI-SCREENSHOT / ENREGISTREMENT
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
}
