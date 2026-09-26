// aegis_app/android/app/src/main/cpp/native_lib.cpp
//
// Pont JNI résiduel pour BlindView.bindSurfaceToNative().
//
// ─────────────────────────────────────────────────────────────────────
// HISTORIQUE DU BUG :
// La version précédente déclarait :
//     extern "C" int32_t aegis_render_to_surface(ANativeWindow* window);
// ce qui provoquait une collision de symbole avec la fonction
// #[no_mangle] pub fn aegis_render_to_surface(JNIEnv, jobject) de
// aegis-core/src/viewer/stream_pipe.rs (error: duplicate symbol au link).
//
// CORRECTIF :
// Toute la logique VRAM est désormais dans aegis-core (Rust). Ce fichier
// ne fait que rediriger vers la méthode native de MainActivity, dont
// l'implémentation Rust est exposée par
//   Java_com_example_aegis_1app_MainActivity_aegis_1render_1to_1surface.
//
// Aucune fonction C++ n'appelle plus directement aegis_render_to_surface.
// ─────────────────────────────────────────────────────────────────────

#include <jni.h>

extern "C" JNIEXPORT void JNICALL
Java_com_example_aegis_1app_BlindView_bindSurfaceToNative(
    JNIEnv* env,
    jobject /* thiz */,
    jobject surface) {

    if (env == nullptr || surface == nullptr) {
        return;
    }

    // Récupération de la classe MainActivity (méthode statique/native).
    jclass main_cls = env->FindClass("com/example/aegis_app/MainActivity");
    if (main_cls == nullptr) {
        // Classe introuvable : purge l'exception Java pendante pour ne
        // pas faire planter le prochain appel JNI.
        env->ExceptionClear();
        return;
    }

    // Signature Kotlin attendue :
    //   companion object {
    //       external fun aegisRenderToSurface(surface: Surface): Int
    //   }
    // → méthode statique → signature JNI "(Landroid/view/Surface;)I".
    jmethodID mid = env->GetStaticMethodID(
        main_cls,
        "aegisRenderToSurface",
        "(Landroid/view/Surface;)I");

    if (mid == nullptr) {
        env->ExceptionClear();
        env->DeleteLocalRef(main_cls);
        return;
    }

    // Appel de la méthode native Rust via la JVM : la résolution est
    // faite par le JVM, qui dispatche vers le symbole exporté par
    // libaegis_core.so. Aucun extern "C" déclaré côté C++ → pas de
    // collision de symbole possible.
    env->CallStaticIntMethod(main_cls, mid, surface);

    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }

    env->DeleteLocalRef(main_cls);
}