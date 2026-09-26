// aegis_app/android/app/build.gradle.kts
//
// CORRECTIF : suppression du bloc orphelin
//   externalNativeBuild { ndkBuild { arguments("NDK_LIBS=-landroid") } }
// qui n'était rattaché à aucun chemin CMake/ndkBuild et était donc
// silencieusement ignoré par AGP (warning "no externalNativeBuild path set").
//
// Le link vers libandroid.so est désormais entièrement piloté par
// aegis-core/build.rs (println!("cargo:rustc-link-lib=android")).
//
// Les .so produits par cargo-ndk doivent être déposés dans
//   android/app/src/main/jniLibs/arm64-v8a/libaegis_core.so
// (répertoire standard AGP).

plugins {
    id("com.android.application")
    id("kotlin-android")
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.example.aegis_app"
    compileSdk = 36
    ndkVersion = "27.0.12077973"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_11.toString()
    }

    defaultConfig {
        applicationId = "com.example.aegis_app"
        minSdk = 23
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName

        // SM-G985F (Galaxy S20+) = arm64-v8a uniquement.
        ndk {
            abiFilters.addAll(setOf("arm64-v8a"))
        }

        // NOTE : ne pas réintroduire externalNativeBuild ici. Les .so Rust
        // sont construits hors Gradle (cargo-ndk) puis déposés dans jniLibs.
    }

    buildTypes {
        release {
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // TODO: replace with a real release signing config before shipping.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

flutter {
    source = "../.."
}

dependencies {
    implementation("androidx.camera:camera-camera2:1.3.1")
    implementation("androidx.camera:camera-lifecycle:1.3.1")
    implementation("androidx.camera:camera-view:1.3.1")
    implementation("com.google.guava:guava:31.1-android")
}