import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:path_provider/path_provider.dart';
import 'package:ffi/ffi.dart';
import 'dart:ffi';
import 'dart:io';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('Test FFI via JVM Preload', (WidgetTester tester) async {
    await tester.pumpWidget(const MaterialApp(home: Scaffold(body: Center(child: Text('FFI')))));
    await tester.pump();

    final Directory tempDir = await getTemporaryDirectory();
    final DynamicLibrary lib = DynamicLibrary.open('libaegis_core.so');
    final initFunc = lib.lookupFunction<Int32 Function(Pointer<Utf8>), int Function(Pointer<Utf8>)>('aegis_init_vault_path');

    final Pointer<Utf8> pathPtr = tempDir.path.toNativeUtf8();
    final int codeRetour = initFunc(pathPtr);
    calloc.free(pathPtr);

    print('--- CODE RETOUR RUST BRUT: ' + codeRetour.toString() + ' ---');
    expect(codeRetour, 0);
  });
}