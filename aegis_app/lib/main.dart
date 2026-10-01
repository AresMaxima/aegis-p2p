import 'dart:async';
import 'dart:convert';
import 'dart:ffi' hide Size;
import 'dart:io';
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_windowmanager_plus/flutter_windowmanager_plus.dart';
import 'package:path_provider/path_provider.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:file_picker/file_picker.dart';
import 'package:permission_handler/permission_handler.dart';

import 'translations.dart'; // IMPORT DU DICTIONNAIRE GLOBAL
import 'views/blind_viewer.dart';
import 'views/camera_capture_screen.dart'; // ← AJOUTÉ
import 'views/steganography_view.dart'; // NOUVEAU MODULE AJOUTÉ
import 'widgets/aegis_keyboard.dart'; // Q3.11 : clavier custom anti-IME
import 'models/session_vault.dart';
import 'services/global_state.dart'; // ← FIX 1 : état partagé
import 'keystore_bridge.dart'; // ← N1 (audit 20/09) : clé StrongBox + F6-C vault

// NOTE : les déclarations `activeRamPin`, `globalSteganoRamBuffer` et
// `isIntentPendingInDart` sont maintenant dans `services/global_state.dart`.
// Ne PAS les redéclarer ici → conflit de symboles.

/// Contrôle d'intégrité binaire et signature APK via le noyau Rust
void verifyApkSignatureOrBurn(String currentApkSha256) {
  try {
    final DynamicLibrary aegisLib = Platform.isAndroid
        ? DynamicLibrary.open('libaegis_core.so')
        : DynamicLibrary.process();

    final void Function(Pointer<Utf8>) verifySign = aegisLib
        .lookup<NativeFunction<Void Function(Pointer<Utf8>)>>('aegis_verify_apk_signature_or_burn')
        .asFunction();

    final ptr = currentApkSha256.toNativeUtf8();
    verifySign(ptr);
    malloc.free(ptr);
  } catch (e) {
    debugPrint("Échec du contrôle de signature APK : $e");
  }
}

/// Validation FFI de la clé de licence client auprès du noyau Rust
bool verifyLicenseKeyFfi(String licenseKey) {
  try {
    final DynamicLibrary aegisLib = Platform.isAndroid
        ? DynamicLibrary.open('libaegis_core.so')
        : DynamicLibrary.process();

    final int Function(Pointer<Utf8>) verifyLic = aegisLib
        .lookup<NativeFunction<Int32 Function(Pointer<Utf8>)>>('aegis_verify_license_key')
        .asFunction();

    final ptr = licenseKey.toNativeUtf8();
    final res = verifyLic(ptr);
    malloc.free(ptr);
    return res == 0;
  } catch (_) {
    return licenseKey.trim().toUpperCase().startsWith("AEGIS-");
  }
}

/// Ingestion tactique Zero-Disk des fichiers (Photos, Vidéos, Documents) en RAM
Future<bool> ingestFileZeroDisk(String filePath) async {
  try {
    final DynamicLibrary aegisLib = Platform.isAndroid
        ? DynamicLibrary.open('libaegis_core.so')
        : DynamicLibrary.process();

    final int Function(Pointer<Utf8>) ingestFunc = aegisLib
        .lookup<NativeFunction<Int32 Function(Pointer<Utf8>)>>('aegis_ingest_file_zero_disk')
        .asFunction();

    final ptr = filePath.toNativeUtf8();
    final result = ingestFunc(ptr);
    malloc.free(ptr);

    return result == 0;
  } catch (e) {
    debugPrint("Erreur lors de l'ingestion Zero-Disk : $e");
    return false;
  }
}

/// Noyage stéganographique FFI dans un poème
String drownKeyFfi(String keyToDrown, String poem) {
  try {
    final DynamicLibrary aegisLib = Platform.isAndroid
        ? DynamicLibrary.open('libaegis_core.so')
        : DynamicLibrary.process();

    final Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>) drownFunc = aegisLib
        .lookup<NativeFunction<Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>>('aegis_stegano_drown_payload')
        .asFunction();

    final void Function(Pointer<Utf8>) freeFunc = aegisLib
        .lookup<NativeFunction<Void Function(Pointer<Utf8>)>>('aegis_free_string')
        .asFunction();

    final keyPtr = keyToDrown.toNativeUtf8();
    final poemPtr = poem.toNativeUtf8();
    final resultPtr = drownFunc(keyPtr, poemPtr);

    if (resultPtr == nullptr) {
      malloc.free(keyPtr);
      malloc.free(poemPtr);
      return "Erreur lors du noyage stéganographique.";
    }

    final resultStr = resultPtr.toDartString();
    freeFunc(resultPtr);
    malloc.free(keyPtr);
    malloc.free(poemPtr);
    return resultStr;
  } catch (_) {
    final encoded = base64Encode(utf8.encode(keyToDrown));
    return "$poem\n\n[AEGIS-STEGO-PAYLOAD:$encoded]";
  }
}

/// Extraction stéganographique FFI depuis un poème
String extractKeyFfi(String stegoText) {
  try {
    final DynamicLibrary aegisLib = Platform.isAndroid
        ? DynamicLibrary.open('libaegis_core.so')
        : DynamicLibrary.process();

    final Pointer<Utf8> Function(Pointer<Utf8>) extractFunc = aegisLib
        .lookup<NativeFunction<Pointer<Utf8> Function(Pointer<Utf8>)>>('aegis_stegano_extract_payload')
        .asFunction();

    final void Function(Pointer<Utf8>) freeFunc = aegisLib
        .lookup<NativeFunction<Void Function(Pointer<Utf8>)>>('aegis_free_string')
        .asFunction();

    final ptr = stegoText.toNativeUtf8();
    final resultPtr = extractFunc(ptr);

    if (resultPtr == nullptr) {
      malloc.free(ptr);
      return "Erreur : Aucun payload stéganographique AEGIS détecté.";
    }

    final resultStr = resultPtr.toDartString();
    freeFunc(resultPtr);
    malloc.free(ptr);
    return resultStr;
  } catch (_) {
    if (!stegoText.contains("[AEGIS-STEGO-PAYLOAD:")) {
      return "Erreur : Aucun payload stéganographique AEGIS détecté.";
    }
    final payload = stegoText.split("[AEGIS-STEGO-PAYLOAD:")[1].split("]")[0];
    return "Clé extraite : ${utf8.decode(base64Decode(payload))}";
  }
}

Future<void> deploySnowflake() async {
  try {
    final directory = await getApplicationDocumentsDirectory();
    final snowflakePath = '${directory.path}/snowflake-client';
    final snowflakeFile = File(snowflakePath);

    if (!await snowflakeFile.exists()) {
      final byteData = await rootBundle.load('assets/bin/snowflake-client');
      await snowflakeFile.writeAsBytes(byteData.buffer.asUint8List(byteData.offsetInBytes, byteData.lengthInBytes));
    }

    if (Platform.isLinux || Platform.isMacOS) {
      await Process.run('chmod', ['+x', snowflakePath]);
    }
  } catch (e) {
    debugPrint("Déploiement Snowflake : $e");
  }
}

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  FlutterError.onError = (FlutterErrorDetails details) {
    FlutterError.presentError(details);
    _executeEmergencyFfiPurge();
  };

  PlatformDispatcher.instance.onError = (error, stack) {
    _executeEmergencyFfiPurge();
    return true;
  };

  if (Platform.isAndroid) {
    const currentApkSha256 = "0E4722F6B404B854848E3FE5A8E66EBD87FFDF8A5FD4C19EDC21323DA5A058D2";
    verifyApkSignatureOrBurn(currentApkSha256);
  }

  try {
    if (Platform.isAndroid) {
      await FlutterWindowManagerPlus.addFlags(FlutterWindowManagerPlus.FLAG_SECURE);
    }
  } catch (e) {
    debugPrint("Erreur FLAG_SECURE : $e");
  }

  await deploySnowflake();

  // ============================================================
  // F6-C (2026-09-30) : configuration du dossier vault (Rust).
  //
  // Cette étape DOIT précéder tout appel vault (isInitialized,
  // initializeMasterPin, unlockSession) et être dans le même
  // contexte que LockScreen (avant runApp).
  //
  // Le dossier utilisé est `getApplicationDocumentsDirectory()`,
  // sous-dossier private du sandbox Android.
  // ============================================================
  try {
    final docsDir = await getApplicationDocumentsDirectory();
    final dirOk = KeystoreBridge.vaultSetDir(docsDir.path);
    debugPrint("AEGIS-VAULT: setVaultDir(${docsDir.path}) = $dirOk");
  } catch (e) {
    debugPrint("AEGIS-VAULT: vaultSetDir a échoué: $e");
  }

  SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
  runApp(const AegisApp());

  // ============================================================
  // N1 (audit 2026-09-20) : initialisation de la clé racine
  // matérielle (StrongBox/TEE) via le canal `com.aegis/keystore`.
  //
  // Flux :
  //   Dart  → MethodChannel.getHardwareSecret
  //   Kotlin → HardwareKeystore.getHardwareSecret() (StrongBox strict)
  //   Kotlin → renvoie 32 octets
  //   Dart  → FFI aegis_set_hardware_secret(ptr, 32)
  //   Rust  → HardwareKeystore::set_root_key() → ROOT_KEY
  //
  // Sans cet appel, `ROOT_KEY` reste `None` côté Rust et toute
  // crypto échoue avec "Root key non initialisée".
  // ============================================================
  WidgetsBinding.instance.addPostFrameCallback((_) async {
    try {
      final ok = await KeystoreBridge.initializeHardwareSecurity(
        isVaultEmpty: false,
      );
      debugPrint("AEGIS: initializeHardwareSecurity = $ok");
    } catch (e) {
      debugPrint("AEGIS: initializeHardwareSecurity a échoué: $e");
    }
  });
}

void _executeEmergencyFfiPurge() {
  try {
    final DynamicLibrary aegisLib = Platform.isAndroid
        ? DynamicLibrary.open('libaegis_core.so')
        : DynamicLibrary.process();

    try {
      final void Function() aegisPurge = aegisLib
          .lookup<NativeFunction<Void Function()>>('aegis_purge_ram_buffer')
          .asFunction();
      aegisPurge();
    } catch (_) {
      final void Function() aegisPanic = aegisLib
          .lookup<NativeFunction<Void Function()>>('aegis_panic_purge')
          .asFunction();
      aegisPanic();
    }
  } catch (_) {}
}

class AegisApp extends StatefulWidget {
  const AegisApp({super.key});

  static void setLocale(BuildContext context, Locale newLocale) {
    _AegisAppState? state = context.findAncestorStateOfType<_AegisAppState>();
    state?.setLocale(newLocale);
  }

  @override
  State<AegisApp> createState() => _AegisAppState();
}

class _AegisAppState extends State<AegisApp> {
  Locale? _locale;

  void setLocale(Locale locale) {
    setState(() {
      _locale = locale;
    });
  }

  @override
  Widget build(BuildContext context) {
    const Color brandYellow = Color(0xFFFCBE0B);

    return MaterialApp(
      title: 'AEGIS P2P',
      debugShowCheckedModeBanner: false,
      locale: _locale,
      supportedLocales: const [
        Locale('fr', 'FR'),
        Locale('en', 'US'),
        Locale('es', 'ES'),
        Locale('ar', 'SA'),
        Locale('it', 'IT'),
        Locale('uk', 'UA'),
        Locale('pl', 'PL'),
      ],
      localeResolutionCallback: (deviceLocale, supportedLocales) {
        if (_locale != null) return _locale;
        for (var locale in supportedLocales) {
          if (deviceLocale != null && deviceLocale.languageCode == locale.languageCode) {
            return locale;
          }
        }
        return const Locale('en', 'US');
      },
      localizationsDelegates: const [
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF000000),
        primaryColor: brandYellow,
        colorScheme: const ColorScheme.dark(primary: brandYellow),
        cardColor: const Color(0xFF141416),
      ),
      // CORRECTION CRITIQUE : Le wrapper englobe TOUTES les routes, il ne sera plus détruit
      builder: (context, child) => UserInactivityWrapper(child: child!),
      home: const LockScreen(),
    );
  }
}

// -----------------------------------------------------------------------------
// INTÉGRATION WIDGETSBINDINGOBSERVER (CYCLE DE VIE OS & VERROUILLAGE D'URGENCE)
// -----------------------------------------------------------------------------
class UserInactivityWrapper extends StatefulWidget {
  final Widget child;
  const UserInactivityWrapper({super.key, required this.child});

  @override
  State<UserInactivityWrapper> createState() => _UserInactivityWrapperState();
}

class _UserInactivityWrapperState extends State<UserInactivityWrapper> with WidgetsBindingObserver {
  Timer? _inactivityTimer;

  // FIX 4 : utilise `isExternalFlowActive()` (compteur + flag booléen)
  // au lieu du flag brut `isIntentPendingInDart`.

  void _lockAndPurge() {
    if (isExternalFlowActive()) return;

    // 1. Purge FFI immédiate de la mémoire RAM
    activeRamPin = "";
    _executeEmergencyFfiPurge();

    // 2. Écrase la mémoire visuelle Flutter (Snapshot OS) vers le code PIN
    runApp(const AegisApp());

    // 3. Fermeture instantanée et brutale à la microseconde
    SystemChannels.platform.invokeMethod('SystemNavigator.pop');
    exit(0);
  }

  void _resetTimer() {
    if (isExternalFlowActive()) return;
    _inactivityTimer?.cancel();
    // Sécurité accrue : verrouillage après 1 minute d'inactivité tactile
    _inactivityTimer = Timer(const Duration(minutes: 1), _lockAndPurge);
  }

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _resetTimer();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _inactivityTimer?.cancel();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (isExternalFlowActive()) return;

    // ────────────────────────────────────────────────────────────────
    // CORRECTIF : ne purge QUE sur un vrai arrière-plan.
    //
    //   • `inactive` : transition transitoire — déclenchée par TOUT dialog
    //     OS (permission caméra, file picker, notification, appel entrant,
    //     aperçu CameraX). L'app est encore visible → NE PAS purger.
    //
    //   • `hidden`   : équivalent API 30+ de `inactive` → NE PAS purger.
    //
    //   • `paused`   : arrière-plan réel (bouton home, changement d'app,
    //     écran verrouillé) → PURGER.
    //
    //   • `detached` : vue Flutter détruite (app fermée) → PURGER.
    // ────────────────────────────────────────────────────────────────
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.detached) {
      _lockAndPurge();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Listener(
      behavior: HitTestBehavior.translucent,
      onPointerDown: (_) => _resetTimer(),
      child: widget.child,
    );
  }
}
// -----------------------------------------------------------------------------

class AegisLogoWidget extends StatelessWidget {
  const AegisLogoWidget({super.key});

  @override
  Widget build(BuildContext context) {
    const brandYellow = Color(0xFFFCBE0B);
    return Container(
      width: 90,
      height: 90,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        border: Border.all(color: brandYellow, width: 3),
        color: const Color(0xFF141416),
        boxShadow: const [
          BoxShadow(color: brandYellow, blurRadius: 10, spreadRadius: -2),
        ],
      ),
      child: ClipOval(
        child: Image.asset(
          'assets/logo.png',
          width: 84,
          height: 84,
          fit: BoxFit.cover,
          errorBuilder: (context, error, stackTrace) => const Center(
            child: Icon(Icons.shield_outlined, size: 50, color: brandYellow),
          ),
        ),
      ),
    );
  }
}

class LockScreen extends StatefulWidget {
  const LockScreen({super.key});

  @override
  State<LockScreen> createState() => _LockScreenState();
}

class _LockScreenState extends State<LockScreen> {
  final TextEditingController _pinController = TextEditingController();
  final TextEditingController _licenseController = TextEditingController();
  final SessionVault _vault = SessionVault();

  bool _isLoading = false;
  bool? _isVaultInitialized;

  // Indicateurs de force du mot de passe (mode création uniquement).
  PasswordStrength? _passwordStrength;
  String? _passwordError;

  @override
  void initState() {
    super.initState();
    _checkVaultState();

    // Écoute la saisie du PIN pour calculer la force en temps réel.
    _pinController.addListener(_onPinChanged);
  }

  void _onPinChanged() {
    if (_isVaultInitialized == false) {
      final pin = _pinController.text;
      if (pin.isEmpty) {
        setState(() {
          _passwordStrength = null;
          _passwordError = null;
        });
        return;
      }
      setState(() {
        _passwordStrength = PasswordValidator.evaluate(pin);
        _passwordError = PasswordValidator.validate(pin);
      });
    }
  }

  Future<void> _checkVaultState() async {
    final initialized = await _vault.isVaultInitialized();
    if (mounted) {
      setState(() {
        _isVaultInitialized = initialized;
      });
    }
  }

  @override
  void dispose() {
    _pinController.removeListener(_onPinChanged);
    _pinController.dispose();
    _licenseController.dispose();
    super.dispose();
  }

  void _triggerSilentBurn() {
    activeRamPin = "";
    try {
      final DynamicLibrary aegisLib = Platform.isAndroid
          ? DynamicLibrary.open('libaegis_core.so')
          : DynamicLibrary.process();

      final void Function() aegisPanicSilentBurn = aegisLib
          .lookup<NativeFunction<Void Function()>>('aegis_panic_silent_burn')
          .asFunction();

      aegisPanicSilentBurn();
    } catch (e) {
      SystemChannels.platform.invokeMethod('SystemNavigator.pop');
      exit(0);
    }
  }

  void _sendDeadmanHeartbeat() {
    try {
      final DynamicLibrary aegisLib = Platform.isAndroid
          ? DynamicLibrary.open('libaegis_core.so')
          : DynamicLibrary.process();

      final void Function() heartbeat = aegisLib
          .lookup<NativeFunction<Void Function()>>('aegis_deadman_heartbeat')
          .asFunction();

      heartbeat();
    } catch (_) {}
  }

  void _unlock() async {
    final pin = _pinController.text.trim();
    final licenseKey = _licenseController.text.trim();

    if (pin.isEmpty) return;

    if (pin == "9999" || pin == "0000") {
      _pinController.clear();
      _triggerSilentBurn();
      return;
    }

    setState(() { _isLoading = true; });

    if (_isVaultInitialized == false) {
      // Validation du mot de passe fort AVANT tout traitement.
      final pwdError = PasswordValidator.validate(pin);
      if (pwdError != null) {
        setState(() { _isLoading = false; });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(pwdError),
            backgroundColor: Colors.orange[800],
          ),
        );
        return;
      }

      if (licenseKey.isNotEmpty && !verifyLicenseKeyFfi(licenseKey)) {
        if (!mounted) return;
        _pinController.clear();
        setState(() { _isLoading = false; });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(AppTranslations.get(context, 'pin_error'))),
        );
        return;
      }

      // F6-C : initializeMasterPin écrit vault.json (verifier HMAC).
      // Il dérive aussi la MASTER_KEY en interne (HKDF ROOT_KEY||PIN).
      final success = await _vault.initializeMasterPin(pin);
      if (!mounted) return;

      if (!success) {
        _pinController.clear();
        _licenseController.clear();
        setState(() { _isLoading = false; });
        return;
      }

      // ============================================================
      // Option 2 (audit 2026-09-20) : dérivation de la master_key.
      // Combine la ROOT_KEY StrongBox (déjà en mémoire Rust) avec le PIN.
      // Note : `vaultInit` a déjà dérivé la MASTER_KEY en interne,
      // cet appel est idempotent (même ROOT_KEY + même PIN → même MK).
      // ============================================================
      final masterOk = await KeystoreBridge.deriveMasterKey(pin);
      if (!mounted) return;

      _pinController.clear();
      _licenseController.clear();
      setState(() { _isLoading = false; });

      if (masterOk) {
        _sendDeadmanHeartbeat();
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(builder: (context) => const MainDashboard()),
        );
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(AppTranslations.get(context, 'toast_master_fail')),
            backgroundColor: Colors.red,
          ),
        );
      }
      return;
    }

    // ----- Vault déjà initialisé : PIN tapé pour déverrouiller -----
    final session = await _vault.unlockSession(pin);
    if (!mounted) return;

    if (session.type == VaultSessionType.real) {
      // ============================================================
      // Mode REAL : on dérive la master_key avec le PIN saisi.
      // Le mode decoy n'appelle PAS deriveMasterKey (pas de fuite timing).
      // ============================================================
      final masterOk = await KeystoreBridge.deriveMasterKey(pin);
      if (!mounted) return;

      _pinController.clear();
      setState(() { _isLoading = false; });

      if (masterOk) {
        _sendDeadmanHeartbeat();
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(builder: (context) => const MainDashboard()),
        );
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(AppTranslations.get(context, 'toast_master_fail')),
            backgroundColor: Colors.red,
          ),
        );
      }
      return;
    }

    // ----- Mode DECOY : navigation sans dérive de clé -----
    _pinController.clear();
    setState(() { _isLoading = false; });
    Navigator.pushReplacement(
      context,
      MaterialPageRoute(builder: (context) => const FakeDashboard()),
    );
  }

  @override
  Widget build(BuildContext context) {
    const Color brandYellow = Color(0xFFFCBE0B);

    if (_isVaultInitialized == null) {
      return const Scaffold(
        backgroundColor: Color(0xFF0D0D0E),
        body: Center(child: CircularProgressIndicator(color: brandYellow)),
      );
    }

    final String displayHint = _isVaultInitialized!
        ? AppTranslations.get(context, 'pin_hint')
        : AppTranslations.get(context, 'create_pin_hint');

    String displayButton = _isVaultInitialized!
        ? AppTranslations.get(context, 'unlock_btn')
        : AppTranslations.get(context, 'init_vault_btn');

    Color buttonColor = _isVaultInitialized! ? brandYellow : Colors.greenAccent;

    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24.0),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const AegisLogoWidget(),
                const SizedBox(height: 16),
                const Text('AEGIS P2P', style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold, letterSpacing: 2, color: brandYellow)),
                Text(AppTranslations.get(context, 'subtitle'), style: const TextStyle(color: Colors.grey, fontSize: 11)),
                const SizedBox(height: 20),
                Builder(
                  builder: (context) {
                    final currentLocale = Localizations.localeOf(context);
                    final safeLocale = const [
                      Locale('fr', 'FR'), Locale('en', 'US'), Locale('es', 'ES'),
                      Locale('ar', 'SA'), Locale('it', 'IT'), Locale('uk', 'UA'), Locale('pl', 'PL')
                    ].firstWhere(
                      (l) => l.languageCode == currentLocale.languageCode,
                      orElse: () => const Locale('en', 'US'),
                    );

                    return DropdownButton<Locale>(
                      value: safeLocale,
                      dropdownColor: const Color(0xFF141416),
                      underline: Container(),
                      items: const [
                        DropdownMenuItem(value: Locale('fr', 'FR'), child: Text('Français')),
                        DropdownMenuItem(value: Locale('en', 'US'), child: Text('English')),
                        DropdownMenuItem(value: Locale('es', 'ES'), child: Text('Español')),
                        DropdownMenuItem(value: Locale('ar', 'SA'), child: Text('العربية')),
                        DropdownMenuItem(value: Locale('it', 'IT'), child: Text('Italiano')),
                        DropdownMenuItem(value: Locale('uk', 'UA'), child: Text('Українська')),
                        DropdownMenuItem(value: Locale('pl', 'PL'), child: Text('Polski')),
                      ],
                      onChanged: (Locale? locale) {
                        if (locale != null) AegisApp.setLocale(context, locale);
                      },
                    );
                  }
                ),
                const SizedBox(height: 16),
                if (_isVaultInitialized == false) ...[
                  TextField(
                    controller: _licenseController,
                    enableInteractiveSelection: false,
                    enabled: !_isLoading,
                    style: const TextStyle(color: brandYellow, letterSpacing: 1),
                    decoration: InputDecoration(
                      hintText: AppTranslations.get(context, 'license_hint'),
                      hintStyle: const TextStyle(color: Colors.white38, fontSize: 11),
                      focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: brandYellow)),
                      border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                    ),
                  ),
                  const SizedBox(height: 12),
                ],
                // Q3.11 (2026-09-26) : remplacement du TextField système par clavier custom.
                // Le PIN ne transite plus par le clavier système (anti-keylogger IME,
                // anti-telemetry Samsung Keyboard / Gboard).
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.symmetric(vertical: 14, horizontal: 12),
                  decoration: BoxDecoration(
                    border: Border.all(color: buttonColor),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Text(
                    _pinController.text.isEmpty
                        ? displayHint
                        : '•' * _pinController.text.length,
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: _pinController.text.isEmpty ? Colors.white54 : Colors.white,
                      letterSpacing: 3,
                      fontSize: 16,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                const SizedBox(height: 12),
                AegisKeyboard(
                  controller: _pinController,
                  onInput: () { setState(() {}); },
                  obscureText: true,
                  brandYellow: buttonColor,
                ),

                // Indicateur de force (visible uniquement en mode création).
                if (_isVaultInitialized == false && _passwordStrength != null) ...[
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      Expanded(
                        child: LinearProgressIndicator(
                          value: (_passwordStrength!.index + 1) / PasswordStrength.values.length,
                          backgroundColor: Colors.white12,
                          valueColor: AlwaysStoppedAnimation<Color>(
                            Color(PasswordValidator.strengthColor(_passwordStrength!)),
                          ),
                          minHeight: 4,
                        ),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        PasswordValidator.strengthLabel(_passwordStrength!),
                        style: TextStyle(
                          color: Color(PasswordValidator.strengthColor(_passwordStrength!)),
                          fontSize: 10,
                          fontWeight: FontWeight.bold,
                          letterSpacing: 1,
                        ),
                      ),
                    ],
                  ),
                  if (_passwordError != null) ...[
                    const SizedBox(height: 6),
                    Text(
                      _passwordError!,
                      style: const TextStyle(color: Colors.white38, fontSize: 10),
                      textAlign: TextAlign.center,
                    ),
                  ],
                ],

                const SizedBox(height: 16),
                ElevatedButton(
                  onPressed: _isLoading ? null : _unlock,
                  style: ElevatedButton.styleFrom(
                    backgroundColor: buttonColor,
                    foregroundColor: Colors.black,
                    minimumSize: const Size(double.infinity, 48),
                  ),
                  child: _isLoading
                      ? const SizedBox(height: 20, width: 20, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.black))
                      : Text(displayButton, style: const TextStyle(fontWeight: FontWeight.bold)),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class FakeDashboard extends StatelessWidget {
  const FakeDashboard({super.key});

  @override
  Widget build(BuildContext context) {
    final decoyNotes = AppTranslations.getDecoyNotes(context);

    return DefaultTabController(
      length: 2,
      child: Scaffold(
        appBar: AppBar(
          title: Text(AppTranslations.get(context, 'fake_dashboard_title')),
          backgroundColor: Colors.grey[900],
          bottom: const TabBar(
            tabs: [
              Tab(icon: Icon(Icons.note), text: "Notes"),
              Tab(icon: Icon(Icons.checklist), text: "Tâches"),
            ],
          ),
        ),
        body: TabBarView(
          children: [
            ListView(
              padding: const EdgeInsets.all(16.0),
              children: decoyNotes[0].map((note) => Card(
                color: const Color(0xFF1C1C1E),
                child: ListTile(
                  title: Text(note['title']!, style: const TextStyle(fontWeight: FontWeight.bold)),
                  subtitle: Text(note['subtitle']!),
                ),
              )).toList(),
            ),
            ListView(
              padding: const EdgeInsets.all(16.0),
              children: decoyNotes[1].map((note) => Card(
                color: const Color(0xFF1C1C1E),
                child: ListTile(
                  leading: const Icon(Icons.check_box_outline_blank, color: Colors.amber),
                  title: Text(note['title']!, style: const TextStyle(fontWeight: FontWeight.bold)),
                  subtitle: Text(note['subtitle']!),
                ),
              )).toList(),
            ),
          ],
        ),
      ),
    );
  }
}

class MainDashboard extends StatefulWidget {
  const MainDashboard({super.key});

  @override
  State<MainDashboard> createState() => _MainDashboardState();
}

class _MainDashboardState extends State<MainDashboard> {
  int _currentIndex = 0;
  final TextEditingController _recipientController = TextEditingController();
  final TextEditingController _chatController = TextEditingController();

  String _networkMode = "t_auto";
  String _connectedPeer = "";
  final String _myEphemeralKey = "AEGIS-P2P-v2.2-GA-4F8B12E9903A7C12D";
  final List<String> _chatMessages = [];

  void _instantRamPurge() {
    _executeEmergencyFfiPurge();
    activeRamPin = "";
    SystemChannels.platform.invokeMethod('SystemNavigator.pop');
    exit(0);
  }

  @override
  void dispose() {
    _recipientController.dispose();
    _chatController.dispose();
    super.dispose();
  }

  Future<void> _pickFileZeroDisk() async {
    beginExternalFlow();
    try {
      FilePickerResult? result = await FilePicker.pickFiles(
        type: FileType.any,
        allowMultiple: false,
        withData: false,
      );

      if (result != null && result.files.isNotEmpty) {
        final String? path = result.files.single.path;
        if (path != null && path.isNotEmpty) {
          final success = await ingestFileZeroDisk(path);
          if (!mounted) return;

          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(success
                  ? AppTranslations.get(context, 'toast_file_ingested')
                  : AppTranslations.get(context, 'toast_file_ingest_fail')),
              backgroundColor: success ? Colors.green : Colors.red,
            ),
          );

          if (success) {
            Navigator.push(
              context,
              MaterialPageRoute(
                builder: (context) => BlindViewerScreen(initialPath: path),
              ),
            );
          }
        }
      }
    } catch (e, stackTrace) {
      debugPrint('[AEGIS-FILE-PICKER] $e\n$stackTrace');
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(AppTranslations.get(context, 'toast_file_error'))),
      );
    } finally {
      endExternalFlow();
    }
  }

  Future<void> _startCameraFromVault() async {
    beginExternalFlow();
    try {
      var status = await Permission.camera.status;
      if (!status.isGranted) {
        status = await Permission.camera.request();
        if (!status.isGranted) {
          if (!mounted) return;
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(AppTranslations.get(context, 'toast_camera_denied')),
              backgroundColor: Colors.red,
            ),
          );
          return;
        }
      }

      if (!mounted) return;

      final captured = await Navigator.push<bool>(
        context,
        MaterialPageRoute(
          builder: (_) => const CameraCaptureScreen(),
          fullscreenDialog: true,
        ),
      );

      if (!mounted) return;
      if (captured != true) return;

      Navigator.push(
        context,
        MaterialPageRoute(
          builder: (_) => const BlindViewerScreen(initialRamCapture: true),
        ),
      );
    } finally {
      endExternalFlow();
    }
  }

  void _openQrScanner() async {
    var status = await Permission.camera.status;
    if (status.isDenied) {
      status = await Permission.camera.request();
    }

    if (!status.isGranted) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(AppTranslations.get(context, 'toast_camera_required'))),
        );
      }
      return;
    }

    if (!mounted) return;

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.black,
      builder: (ctx) => SizedBox(
        height: 420,
        child: Column(
          children: [
            AppBar(
              title: Text(AppTranslations.get(context, 'scan_qr')),
              backgroundColor: Colors.grey[900],
              leading: IconButton(
                icon: const Icon(Icons.close),
                onPressed: () => Navigator.pop(ctx),
              ),
            ),
            Expanded(
              child: MobileScanner(
                onDetect: (capture) {
                  for (final barcode in capture.barcodes) {
                    if (barcode.rawValue != null) {
                      setState(() {
                        _recipientController.text = barcode.rawValue!;
                        _connectedPeer = barcode.rawValue!;
                      });
                      Navigator.pop(ctx);
                      break;
                    }
                  }
                },
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _showMyQrCode() {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF141416),
        title: Text(AppTranslations.get(context, 'show_qr'), style: const TextStyle(color: Color(0xFFFCBE0B))),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.all(16),
              color: Colors.white,
              child: const Icon(Icons.qr_code_2, size: 140, color: Colors.black),
            ),
            const SizedBox(height: 12),
            SelectableText(
              _myEphemeralKey,
              style: const TextStyle(color: Colors.greenAccent, fontSize: 11),
              textAlign: TextAlign.center,
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: _myEphemeralKey));
              Navigator.pop(ctx);
            },
            child: Text(AppTranslations.get(context, 'copy_key'), style: const TextStyle(color: Color(0xFFFCBE0B))),
          ),
        ],
      ),
    );
  }

  Widget _buildNetworkTab() {
    const brandYellow = Color(0xFFFCBE0B);
    return ListView(
      padding: const EdgeInsets.all(16.0),
      children: [
        Text(AppTranslations.get(context, 'network_mode'), style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.white54)),
        const SizedBox(height: 8),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 12),
          decoration: BoxDecoration(color: const Color(0xFF141416), borderRadius: BorderRadius.circular(8)),
          child: DropdownButtonHideUnderline(
            child: DropdownButton<String>(
              value: _networkMode,
              isExpanded: true,
              dropdownColor: const Color(0xFF141416),
              items: [
                DropdownMenuItem(value: "t_tor", child: Text(AppTranslations.get(context, 't_tor'))),
                DropdownMenuItem(value: "t_wan", child: Text(AppTranslations.get(context, 't_wan'))),
                DropdownMenuItem(value: "t_lan", child: Text(AppTranslations.get(context, 't_lan'))),
                DropdownMenuItem(value: "t_auto", child: Text(AppTranslations.get(context, 't_auto'))),
              ],
              onChanged: (val) { if (val != null) setState(() => _networkMode = val); },
            ),
          ),
        ),
        const SizedBox(height: 24),
        Text(AppTranslations.get(context, 'my_address'), style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.white54)),
        const SizedBox(height: 8),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(12.0),
          decoration: BoxDecoration(color: const Color(0xFF141416), borderRadius: BorderRadius.circular(8)),
          child: SelectableText(_myEphemeralKey, style: const TextStyle(color: Colors.greenAccent, fontFamily: 'monospace')),
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Expanded(child: OutlinedButton.icon(onPressed: _showMyQrCode, icon: const Icon(Icons.qr_code, color: brandYellow), label: Text(AppTranslations.get(context, 'show_qr'), style: const TextStyle(color: Colors.white)))),
            const SizedBox(width: 8),
            Expanded(child: OutlinedButton.icon(onPressed: _openQrScanner, icon: const Icon(Icons.qr_code_scanner, color: Colors.greenAccent), label: Text(AppTranslations.get(context, 'scan_qr'), style: const TextStyle(color: Colors.white)))),
          ],
        ),
        const SizedBox(height: 32),
        TextField(
          controller: _recipientController,
          enableInteractiveSelection: false,
          decoration: InputDecoration(
            hintText: AppTranslations.get(context, 'recipient_address'),
            filled: true, fillColor: const Color(0xFF141416),
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide.none),
          ),
        ),
        const SizedBox(height: 12),
        ElevatedButton(
          onPressed: () {
            if (_recipientController.text.isNotEmpty) setState(() => _connectedPeer = _recipientController.text);
          },
          style: ElevatedButton.styleFrom(backgroundColor: brandYellow, foregroundColor: Colors.black, minimumSize: const Size(double.infinity, 48)),
          child: Text(AppTranslations.get(context, 'connect_peer'), style: const TextStyle(fontWeight: FontWeight.bold)),
        ),
        const SizedBox(height: 8),
        Center(
          child: Text(
            _connectedPeer.isNotEmpty ? "${AppTranslations.get(context, 'peer_connected')} $_connectedPeer" : AppTranslations.get(context, 'peer_none'),
            style: TextStyle(color: _connectedPeer.isNotEmpty ? Colors.greenAccent : Colors.white38, fontSize: 12),
          ),
        ),
      ],
    );
  }

  Widget _buildChatTab() {
    return ListView(
      padding: const EdgeInsets.all(16.0),
      children: [
        const SteganographyView(),
        const Divider(height: 40, color: Color(0xFF2C2C2E)),
        Text(AppTranslations.get(context, 'chat_title'), style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.white54)),
        const SizedBox(height: 8),
        Container(
          height: 200,
          decoration: BoxDecoration(color: const Color(0xFF141416), borderRadius: BorderRadius.circular(8)),
          child: _chatMessages.isEmpty
              ? Center(child: Text(AppTranslations.get(context, 'chat_empty'), style: const TextStyle(color: Colors.white38)))
              : ListView.builder(
                  padding: const EdgeInsets.all(8),
                  itemCount: _chatMessages.length,
                  itemBuilder: (context, idx) => Padding(padding: const EdgeInsets.only(bottom: 4), child: Text(_chatMessages[idx])),
                ),
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Expanded(
              child: TextField(
                controller: _chatController,
                enableInteractiveSelection: false,
                decoration: InputDecoration(
                  hintText: AppTranslations.get(context, 'chat_hint'),
                  filled: true, fillColor: const Color(0xFF141416),
                  border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide.none),
                ),
              ),
            ),
            const SizedBox(width: 8),
            Container(
              decoration: BoxDecoration(color: const Color(0xFFFCBE0B), borderRadius: BorderRadius.circular(8)),
              child: IconButton(
                icon: const Icon(Icons.send, color: Colors.black),
                onPressed: () {
                  if (_chatController.text.isNotEmpty) {
                    setState(() { _chatMessages.add("Moi: ${_chatController.text}"); _chatController.clear(); });
                  }
                },
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildVaultTab() {
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.folder_special, size: 80, color: Colors.white12),
          const SizedBox(height: 24),

          ElevatedButton.icon(
            onPressed: _startCameraFromVault,
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFFD4AF37),
              foregroundColor: Colors.black,
              minimumSize: const Size(double.infinity, 56),
            ),
            icon: const Icon(Icons.camera_alt_sharp),
            label: Text(
              AppTranslations.get(context, 'btn_capture'),
              style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
            ),
          ),

          const SizedBox(height: 12),

          ElevatedButton.icon(
            onPressed: _pickFileZeroDisk,
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFFFCBE0B),
              foregroundColor: Colors.black,
              minimumSize: const Size(double.infinity, 56),
            ),
            icon: const Icon(Icons.add_to_drive),
            label: Text(
              AppTranslations.get(context, 'media_select_btn'),
              style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
            ),
          ),

          const SizedBox(height: 16),
          Text(
            AppTranslations.get(context, 'vault_ingestion_note'),
            textAlign: TextAlign.center,
            style: TextStyle(color: Colors.grey[600], fontSize: 12),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(AppTranslations.get(context, 'dashboard_title'), style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
        backgroundColor: Colors.black,
        elevation: 0,
        actions: [
          IconButton(
            icon: const Icon(Icons.warning_amber_rounded, color: Colors.redAccent, size: 28),
            tooltip: "PURGE D'URGENCE",
            onPressed: _instantRamPurge,
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: IndexedStack(
        index: _currentIndex,
        children: [
          _buildNetworkTab(),
          _buildChatTab(),
          _buildVaultTab(),
        ],
      ),
      bottomNavigationBar: BottomNavigationBar(
        backgroundColor: const Color(0xFF141416),
        selectedItemColor: const Color(0xFFFCBE0B),
        unselectedItemColor: Colors.white38,
        currentIndex: _currentIndex,
        onTap: (index) => setState(() => _currentIndex = index),
        items: [
          BottomNavigationBarItem(icon: const Icon(Icons.cell_tower), label: AppTranslations.get(context, 'tab_network')),
          BottomNavigationBarItem(icon: const Icon(Icons.forum), label: AppTranslations.get(context, 'tab_chat')),
          BottomNavigationBarItem(icon: const Icon(Icons.shield), label: AppTranslations.get(context, 'tab_vault')),
        ],
      ),
    );
  }
}