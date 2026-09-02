import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';
import 'package:aegis_app/ffi_bindings.dart';
import 'dart:io';

void main() {
  // 1. Suppression totale des logs en production
  if (kReleaseMode) {
    debugPrint = (String? message, {int? wrapWidth}) {};
  }

  // 2. Interception des crashs synchrones (Erreurs de rendu UI)
  FlutterError.onError = (FlutterErrorDetails details) {
    if (kReleaseMode) {
      AegisNativeBindings.panicPurge();
      exit(137);
    } else {
      FlutterError.presentError(details);
    }
  };

  // 3. Interception des crashs asynchrones (Isolates, Futures, Réseau)
  PlatformDispatcher.instance.onError = (error, stack) {
    if (kReleaseMode) {
      AegisNativeBindings.panicPurge();
      exit(137);
    }
    return true;
  };

  runApp(const AegisApp());
}

class AegisApp extends StatelessWidget {
  const AegisApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      home: Scaffold(
        backgroundColor: Colors.black,
        body: Center(
          child: Text(
            'AEGIS UI SECURE',
            style: TextStyle(color: Colors.greenAccent),
          ),
        ),
      ),
    );
  }
}