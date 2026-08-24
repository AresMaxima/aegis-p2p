package com.example.aegis_app

import android.os.Process
import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine

class MainActivity: FlutterActivity() {

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        // Protection matérielle anti-capture/enregistrement d'écran (Étape 1.3)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    override fun onPause() {
        super.onPause()
        // Destruction immédiate du processus dès la mise en arrière-plan
        Process.killProcess(Process.myPid())
        System.exit(137)
    }

    override fun onStop() {
        super.onStop()
        Process.killProcess(Process.myPid())
        System.exit(137)
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        // Destruction instantanée si pop-up système, volet de notification ou perte de focus
        if (!hasFocus) {
            Process.killProcess(Process.myPid())
            System.exit(137)
        }
    }
}
