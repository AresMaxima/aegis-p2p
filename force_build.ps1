// aegis-core/build.rs
//
// Directives de link pour le NDK Android.
//
// Les symboles NDK utilisés par `src/viewer/stream_pipe.rs` :
//   • ANativeWindow_fromSurface
//   • ANativeWindow_release
//   • ANativeWindow_setBuffersGeometry
//   • ANativeWindow_lock
//   • ANativeWindow_unlockAndPost
//
// Tous sont dans `libandroid.so`. La bibliothèque `libnativewindow.so`
// existe sur le device mais n'est PAS exposée dans le sysroot NDK → il
// est interdit de la linker (ld.lld échoue avec "unable to find library").
//
//   • liblog.so → __android_log_print (utilisé indirectement par les
//     dépendances natives qui loguent, ex: ring, arti-client).

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if target_os == "android" {
        println!("cargo:rustc-link-lib=android");
        println!("cargo:rustc-link-lib=log");
    }
}