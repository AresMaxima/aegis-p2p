#include <jni.h>
#include <android/native_window_jni.h>
#include <android/native_window.h>

extern "C" {
    // Déclaration de la fonction FFI exposée par aegis-core (Rust)
    int32_t aegis_render_to_surface(ANativeWindow* window);
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_aegis_1app_BlindView_bindSurfaceToNative(JNIEnv* env, jobject thiz, jobject surface) {
    // Extraction stricte de la surface matérielle VRAM
    ANativeWindow* window = ANativeWindow_fromSurface(env, surface);
    if (window != nullptr) {
        // Rust prend le contrôle direct du pipeline VRAM
        aegis_render_to_surface(window);
        ANativeWindow_release(window);
    }
}