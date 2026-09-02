cmake_minimum_required(VERSION 3.10.2)

project(aegis_jni)

# Forcer la vérification de l'architecture 64-bit
if(NOT ANDROID_ABI STREQUAL "arm64-v8a")
    message(WARNING "Architecture non supportée: ${ANDROID_ABI}. AEGIS exige arm64-v8a.")
endif()

add_library(aegis_jni SHARED native_lib.cpp)

# Trouver la bibliothèque système Android pour Native Window / Hardware Composer
find_library(android-lib android)

# Déclarer le binaire Rust importé
add_library(aegis_core SHARED IMPORTED)
set_target_properties(aegis_core PROPERTIES IMPORTED_LOCATION
    ${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libaegis_core.so)

# Lier les dépendances
target_link_libraries(aegis_jni ${android-lib} aegis_core)