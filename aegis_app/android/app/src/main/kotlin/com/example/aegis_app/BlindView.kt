package com.example.aegis_app

import android.content.Context
import android.util.Log
import android.view.SurfaceHolder
import android.view.SurfaceView
import io.flutter.plugin.platform.PlatformView

class BlindView(
    context: Context,
    id: Int,
    creationParams: Map<String?, Any?>?
) : PlatformView, SurfaceHolder.Callback {

    companion object {
        private const val TAG = "BlindView"
    }

    private val surfaceView = SurfaceView(context)

    // =====================================================================
    // Référence vers MainActivity
    // =====================================================================
    //
    // CORRECTIF : Flutter PlatformView fournit un ContextThemeWrapper autour
    // de l'Activity, pas MainActivity directement. On traverse la chaîne
    // ContextWrapper jusqu'à trouver l'Activity réelle.
    //
    // Sans ce fix, `context as? MainActivity` retourne null → surfaceCreated
    // ne peut jamais appeler aegis_render_to_surface() → surface VRAM jamais
    // liée → AFFICHER retourne -5 ("surface non prête").
    private val activity: MainActivity? = context.findMainActivity()

    private fun Context.findMainActivity(): MainActivity? {
        var ctx: Context? = this
        while (ctx is android.content.ContextWrapper) {
            if (ctx is MainActivity) return ctx
            ctx = ctx.baseContext
        }
        return null
    }

    init {
        surfaceView.holder.addCallback(this)
    }

    override fun getView() = surfaceView

    // =====================================================================
    // Cycle de vie de la Surface
    // =====================================================================

    override fun surfaceCreated(holder: SurfaceHolder) {
        val act = activity
        if (act == null) {
            Log.e(TAG, "Contexte non-MainActivity, JNI indisponible")
            return
        }
        try {
            // Acquiert un ANativeWindow* côté Rust et le lie au StreamPipe.
            act.aegis_render_to_surface(holder.surface)
        } catch (t: Throwable) {
            Log.e(TAG, "aegis_render_to_surface a échoué", t)
        }
    }

    override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {
        // Rien à faire : le rendu natif se base sur le ANativeWindow* déjà acquis.
    }

    override fun surfaceDestroyed(holder: SurfaceHolder) {
        // La surface est détruite (rotation, mise en arrière-plan, fermeture).
        // On libère l'ANativeWindow côté Rust pour éviter toute fuite GPU.
        try {
            activity?.aegis_release_surface()
        } catch (t: Throwable) {
            Log.w(TAG, "aegis_release_surface (surfaceDestroyed) a échoué", t)
        }
    }

    // =====================================================================
    // Destruction du PlatformView
    // =====================================================================

    override fun dispose() {
        try {
            surfaceView.holder.removeCallback(this)
            // CORRECTIF : même problème que pour `activity` ci-dessus,
            // surfaceView.context est un ContextThemeWrapper, pas MainActivity.
            // On réutilise la propriété `activity` déjà résolue.
            //
            // Idempotent : libère l'ANativeWindow* s'il en reste un côté Rust.
            // (surfaceDestroyed a déjà pu le libérer ; le double appel est sans effet.)
            activity?.aegis_release_surface()
        } catch (t: Throwable) {
            Log.w(TAG, "dispose error", t)
        }
    }
}