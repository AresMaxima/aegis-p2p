-keep class com.example.aegis_app.** { *; }
-keepclassmembers class com.example.aegis_app.** { *; }
-keep class com.aegis.** { *; }
-keep class **.HardwareKeystore { *; }
-keepclassmembers class **.HardwareKeystore { *; }

-keepclassmembers class * {
    native <methods>;
    @androidx.annotation.Keep *;
}

-keep class io.flutter.plugin.common.** { *; }
-keepclassmembers class * implements io.flutter.plugin.common.MethodChannel$MethodCallHandler { *; }

-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod

-dontwarn com.google.android.play.core.**
-dontwarn io.flutter.embedding.engine.deferredcomponents.**
