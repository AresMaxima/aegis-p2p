import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:aegis_app/ffi_bindings.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('Test FFI direct sur puce ARM64', (WidgetTester tester) async {
    expect(() => AegisNativeBindings.initVaultPath('.'), returnsNormally);
  });
}
