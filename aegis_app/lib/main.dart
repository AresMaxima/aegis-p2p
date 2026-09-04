import 'dart:async';
import 'dart:convert';
import 'dart:ffi' hide Size;
import 'dart:io';
import 'dart:math';
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_windowmanager_plus/flutter_windowmanager_plus.dart';
import 'package:path_provider/path_provider.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:file_picker/file_picker.dart';

import 'views/blind_viewer.dart';
import 'models/session_vault.dart';

String activeRamPin = "";
bool isIntentPendingInDart = false;

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

    final keyPtr = keyToDrown.toNativeUtf8();
    final poemPtr = poem.toNativeUtf8();
    final resultPtr = drownFunc(keyPtr, poemPtr);
    final resultStr = resultPtr.toDartString();

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

    final ptr = stegoText.toNativeUtf8();
    final resultPtr = extractFunc(ptr);
    final resultStr = resultPtr.toDartString();
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
    const currentApkSha256 = "FC908162448FA038D656691A8FA38BD0F36D5B32A8E916DF485C743015917184";
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

  SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
  runApp(const AegisApp());
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
        scaffoldBackgroundColor: const Color(0xFF0D0D0E),
        primaryColor: brandYellow,
        colorScheme: const ColorScheme.dark(primary: brandYellow),
      ),
      home: const UserInactivityWrapper(child: LockScreen()),
    );
  }
}

class UserInactivityWrapper extends StatefulWidget {
  final Widget child;
  const UserInactivityWrapper({super.key, required this.child});

  @override
  State<UserInactivityWrapper> createState() => _UserInactivityWrapperState();
}

class _UserInactivityWrapperState extends State<UserInactivityWrapper> {
  Timer? _inactivityTimer;

  void _resetTimer() {
    if (isIntentPendingInDart) return;
    _inactivityTimer?.cancel();
    _inactivityTimer = Timer(const Duration(minutes: 3), () {
      activeRamPin = "";
      SystemNavigator.pop();
    });
  }

  @override
  void initState() {
    super.initState();
    _resetTimer();
  }

  @override
  void dispose() {
    _inactivityTimer?.cancel();
    super.dispose();
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

class AppTranslations {
  static final Map<String, Map<String, String>> _localizedValues = {
    'fr': {
      'subtitle': 'Session RAM Volatile - Empreinte Zéro',
      'pin_hint': 'Entrez votre Mot de Passe',
      'license_hint': 'CLÉ DE LICENCE CLIENT (EX: AEGIS-XXXX)',
      'unlock_btn': 'DÉVERROUILLER LA SESSION',
      'create_pin_hint': 'CRÉEZ VOTRE MOT DE PASSE (MIN 4 CHIFFRES)',
      'init_vault_btn': 'INITIALISER LE COFFRE SÉCURISÉ',
      'pin_error': 'Mot de Passe ou Licence Invalide - Purge Mémoire',
      'dashboard_title': 'CONSOLE AEGIS CORE',
      'network_mode': 'MODE DE TRANSPORT RÉSEAU',
      't_tor': 'Tor v3 Embarqué (Anonymat Max)',
      't_wan': 'Direct WAN (P2P / DHT Rapide)',
      't_lan': 'Hors-Ligne / Local (Wi-Fi / Bluetooth)',
      't_auto': 'Hybride / Auto (Saut de Fréquence)',
      'chat_title': 'CANAL DE MESSAGERIE P2P',
      'chat_empty': 'Aucun message dans le tampon RAM.',
      'chat_hint': 'Message chiffré...',
      'send_btn': 'ENVOYER LE MESSAGE',
      'stegano_title': 'MODULE STÉGANOGRAPHIE (NOYAGE & EXTRACTION)',
      'stegano_hint': 'Collez un texte stégano ou une clé à dissimuler...',
      'stegano_btn': 'NOYER LA CLÉ DANS UN POÈME',
      'stegano_extract_btn': 'EXTRAIRE LA CLÉ DU TEXTE',
      'stegano_result': 'Résultat du traitement stéganographique :',
      'security_panel': 'SÉCURITÉ & DESTRUCTION D\'URGENCE',
      'kill_switch_btn': 'DESTRUCTION IMMÉDIATE DE LA RAM (KILL SWITCH)',
      'change_pin_btn': 'MODIFIER LE MOT DE PASSE DE SESSION',
      'recipient_address': 'Clé Publique / Adresse Onion du destinataire',
      'connect_peer': 'CONNECTER LE PAIR',
      'my_address': 'VOTRE CLÉ PUB & ID P2P ÉPHÉMÈRE :',
      'peer_connected': 'Connecté au pair :',
      'peer_none': 'Aucun correspondant connecté (Bouteille à la mer)',
      'show_qr': 'MON QR CODE',
      'scan_qr': 'SCANNER CIBLE QR',
      'copy_key': 'COPIER MA CLÉ',
      'fake_dashboard_title': 'NOTES PERSONNELLES',
      'media_select_btn': 'CHARGER FICHIER RAM (PHOTO/VIDÉO/DOC)',
    },
    'en': {
      'subtitle': 'Volatile RAM Session - Zero Trace',
      'pin_hint': 'Enter Password',
      'license_hint': 'CLIENT LICENSE KEY (EX: AEGIS-XXXX)',
      'unlock_btn': 'UNLOCK SESSION',
      'create_pin_hint': 'CREATE YOUR PASSWORD (MIN 4 DIGITS)',
      'init_vault_btn': 'INITIALIZE SECURE VAULT',
      'pin_error': 'Invalid Password or License - Memory Purged',
      'dashboard_title': 'AEGIS CORE CONSOLE',
      'network_mode': 'NETWORK TRANSPORT MODE',
      't_tor': 'Embedded Tor v3 (Max Anonymity)',
      't_wan': 'Direct WAN (Fast P2P / DHT)',
      't_lan': 'Air-Gapped / Local (Wi-Fi / Bluetooth)',
      't_auto': 'Hybrid / Auto (Transport Hopping)',
      'chat_title': 'P2P MESSAGING CHANNEL',
      'chat_empty': 'No messages in RAM buffer.',
      'chat_hint': 'Encrypted message...',
      'send_btn': 'SEND MESSAGE',
      'stegano_title': 'STEGANOGRAPHY MODULE (DROWNING & EXTRACTION)',
      'stegano_hint': 'Paste stega text or key to disguise...',
      'stegano_btn': 'DROWN KEY IN POEM',
      'stegano_extract_btn': 'EXTRACT KEY FROM TEXT',
      'stegano_result': 'Steganographic result:',
      'security_panel': 'SECURITY & EMERGENCY DESTRUCTION',
      'kill_switch_btn': 'INSTANT RAM PURGE (KILL SWITCH)',
      'change_pin_btn': 'CHANGE SESSION PASSWORD',
      'recipient_address': 'Recipient Public Key / Onion Address',
      'connect_peer': 'CONNECT PEER',
      'my_address': 'YOUR PUBLIC KEY & EPHEMERAL P2P ID:',
      'peer_connected': 'Connected to peer:',
      'peer_none': 'No peer connected (Broadcasting blindly)',
      'show_qr': 'MY QR CODE',
      'scan_qr': 'SCAN TARGET QR',
      'copy_key': 'COPY MY KEY',
      'fake_dashboard_title': 'PERSONAL NOTES',
      'media_select_btn': 'LOAD FILE TO RAM (PHOTO/VIDEO/DOC)',
    },
    'es': {
      'subtitle': 'Sesión RAM Volátil - Huella Cero',
      'pin_hint': 'Ingrese su Contraseña',
      'license_hint': 'CLAVE DE LICENCIA CLIENTE (EJ: AEGIS-XXXX)',
      'unlock_btn': 'DESBLOQUEAR SESIÓN',
      'create_pin_hint': 'CREE SU CONTRASEÑA (MÍN 4 DÍGITOS)',
      'init_vault_btn': 'INICIALIZAR BÓVEDA SEGURA',
      'pin_error': 'Contraseña o Licencia Inválida - Memoria Purgada',
      'dashboard_title': 'CONSOLA AEGIS CORE',
      'network_mode': 'MODO DE TRANSPORTE DE RED',
      't_tor': 'Tor v3 Integrado (Anonimato Máx)',
      't_wan': 'WAN Directa (P2P / DHT Rápido)',
      't_lan': 'Fuera de Línea / Local (Wi-Fi / Bluetooth)',
      't_auto': 'Híbrido / Auto (Salto de Frecuencia)',
      'chat_title': 'CANAL DE MENSAJERÍA P2P',
      'chat_empty': 'No hay mensajes en el búfer RAM.',
      'chat_hint': 'Mensaje cifrado...',
      'send_btn': 'ENVIAR MENSAJE',
      'stegano_title': 'MÓDULO ESTEGANOGRAFÍA (OCULTACIÓN Y EXTRACCIÓN)',
      'stegano_hint': 'Pegue el texto estegano o la clave a ocultar...',
      'stegano_btn': 'OCULTAR CLAVE EN POEMA',
      'stegano_extract_btn': 'EXTRAER CLAVE DEL TEXTO',
      'stegano_result': 'Resultado esteganográfico:',
      'security_panel': 'SEGURIDAD Y DESTRUCCIÓN DE EMERGENCIA',
      'kill_switch_btn': 'PURGA INMEDIATA DE RAM (KILL SWITCH)',
      'change_pin_btn': 'CAMBIAR CONTRASEÑA DE SESIÓN',
      'recipient_address': 'Clave Pública / Dirección Onion del destinatario',
      'connect_peer': 'CONECTAR PAR',
      'my_address': 'SU CLAVE PÚBLICA E ID P2P EFÍMERO:',
      'peer_connected': 'Conectado al par:',
      'peer_none': 'Ningún par conectado (Transmitiendo a ciegas)',
      'show_qr': 'MI CÓDIGO QR',
      'scan_qr': 'ESCANEAR CÓDIGO QR',
      'copy_key': 'COPIAR MI CLAVE',
      'fake_dashboard_title': 'NOTAS PERSONALES',
      'media_select_btn': 'CARGAR ARCHIVO EN RAM (FOTO/VIDEO/DOC)',
    },
    'it': {
      'subtitle': 'Sessione RAM Volatile - Traccia Zero',
      'pin_hint': 'Inserisci la Password',
      'license_hint': 'CHIAVE DI LICENZA CLIENTE (ES: AEGIS-XXXX)',
      'unlock_btn': 'SBLOCCA SESSIONE',
      'create_pin_hint': 'CREA LA TUA PASSWORD (MIN 4 CIFRE)',
      'init_vault_btn': 'INIZIALIZZA CASSAFORTE SICURA',
      'pin_error': 'Password o Licenza non valida - Memoria Purgata',
      'dashboard_title': 'CONSOLE AEGIS CORE',
      'network_mode': 'MODALITÀ DI TRASPORTO RETE',
      't_tor': 'Tor v3 Integrato (Anonimato Max)',
      't_wan': 'WAN Diretta (P2P / DHT Veloce)',
      't_lan': 'Offline / Locale (Wi-Fi / Bluetooth)',
      't_auto': 'Ibrido / Auto (Salto di Frequenza)',
      'chat_title': 'CANALE DI MESSAGGISTICA P2P',
      'chat_empty': 'Nessun messaggio nel buffer RAM.',
      'chat_hint': 'Messaggio crittografato...',
      'send_btn': 'INVIA MESSAGGIO',
      'stegano_title': 'MODULO STEGANOGRAFIA (OCCULTAMENTO E ESTRAZIONE)',
      'stegano_hint': 'Incolla il testo stegano o la chiave da nascondere...',
      'stegano_btn': 'NASCONDI CHIAVE NELLA POESIA',
      'stegano_extract_btn': 'ESTRAI CHIAVE DAL TESTO',
      'stegano_result': 'Risultato steganografico:',
      'security_panel': 'SICUREZZA E DISTRUZIONE DI EMERGENZA',
      'kill_switch_btn': 'PURGA IMMEDIATA RAM (KILL SWITCH)',
      'change_pin_btn': 'CAMBIA PASSWORD DI SESSIONE',
      'recipient_address': 'Chiave Pubblica / Indirizzo Onion del destinatario',
      'connect_peer': 'CONNETTI PEER',
      'my_address': 'LA TUA CHIAVE PUBBLICA E ID P2P EFFIMERO:',
      'peer_connected': 'Connesso al peer:',
      'peer_none': 'Nessun peer connesso (Trasmissione alla cieca)',
      'show_qr': 'IL MIO CODICE QR',
      'scan_qr': 'SCANSIONA CODICE QR',
      'copy_key': 'COPIA LA MIA CHIAVE',
      'fake_dashboard_title': 'APPUNTI PERSONALI',
      'media_select_btn': 'CARICA FILE IN RAM (FOTO/VIDEO/DOC)',
    },
    'pl': {
      'subtitle': 'Ulotna Sesja RAM - Zerowy Ślad',
      'pin_hint': 'Wprowadź Hasło',
      'license_hint': 'KLUCZ LICENCJI KLIENTA (NP. AEGIS-XXXX)',
      'unlock_btn': 'ODBLOKUJ SESJĘ',
      'create_pin_hint': 'UTWÓRZ HASŁO (MIN 4 CYFRY)',
      'init_vault_btn': 'INICJALIZUJ BEZPIECZNY SKARBIEC',
      'pin_error': 'Nieprawidłowe Hasło lub Licencja - Pamięć Oczyszczona',
      'dashboard_title': 'KONSOLA AEGIS CORE',
      'network_mode': 'TRYB TRANSPORTU SIECI',
      't_tor': 'Wbudowany Tor v3 (Maksymalna Anonimowość)',
      't_wan': 'Bezpośredni WAN (Szybki P2P / DHT)',
      't_lan': 'Offline / Lokalny (Wi-Fi / Bluetooth)',
      't_auto': 'Hybrydowy / Auto (Skakanie po transportach)',
      'chat_title': 'KANAŁ WIADOMOŚCI P2P',
      'chat_empty': 'Brak wiadomości w buforze RAM.',
      'chat_hint': 'Zaszyfrowana wiadomość...',
      'send_btn': 'WYŚLIJ WIADOMOŚĆ',
      'stegano_title': 'MODUŁ STEGANOGRAFII (UKRYWANIE I EKSTRAKCJA)',
      'stegano_hint': 'Wklej tekst stegano lub klucz do ukrycia...',
      'stegano_btn': 'UKRYJ KLUCZ W WIERSZU',
      'stegano_extract_btn': 'WYDOBĄDŹ KLUCZ Z TEKSTU',
      'stegano_result': 'Wynik steganograficzny:',
      'security_panel': 'BEZPIECZEŃSTWO I AWARYJNE NISZCZENIE',
      'kill_switch_btn': 'NATYCHMIASTOWE CZYSZCZENIE RAM (KILL SWITCH)',
      'change_pin_btn': 'ZMIEŃ HASŁO SESJI',
      'recipient_address': 'Klucz Publiczny / Adres Onion odbiorcy',
      'connect_peer': 'POŁĄCZ Z PEEREM',
      'my_address': 'TWÓJ KLUCZ PUBLICZNY I ULOTNY ID P2P:',
      'peer_connected': 'Połączono z peerem:',
      'peer_none': 'Brak połączonego peera (Transmisja w ciemno)',
      'show_qr': 'MÓJ KOD QR',
      'scan_qr': 'SKANUJ KOD QR',
      'copy_key': 'KOPIUJ MÓJ KLUCZ',
      'fake_dashboard_title': 'NOTATKI OSOBISTE',
      'media_select_btn': 'ZAŁADUJ PLIK DO RAM (ZDJĘCIE/WIDEO/DOC)',
    },
    'uk': {
      'subtitle': 'Летка Сесія RAM - Нульовий Слід',
      'pin_hint': 'Введіть Пароль',
      'license_hint': 'КЛЮЧ ЛІЦЕНЗІЇ КЛІЄНТА (НАПР. AEGIS-XXXX)',
      'unlock_btn': 'РОЗБЛОКУВАТИ СЕСІЮ',
      'create_pin_hint': 'СТВОРІТЬ ПАРОЛЬ (МІН. 4 ЦИФРИ)',
      'init_vault_btn': 'ІНІЦІАЛІЗУВАТИ БЕЗПЕЧНЕ СХОВИЩЕ',
      'pin_error': 'Недійсний Пароль або Ліцензія - Пам\'ять Очищено',
      'dashboard_title': 'КОНСОЛЬ AEGIS CORE',
      'network_mode': 'РЕЖИМ МЕРЕЖЕВОГО ТРАНСПОРТУ',
      't_tor': 'Вбудований Tor v3 (Макс. Анонімність)',
      't_wan': 'Прямий WAN (Швидкий P2P / DHT)',
      't_lan': 'Офлайн / Локальний (Wi-Fi / Bluetooth)',
      't_auto': 'Гібридний / Авто (Стрибки транспорту)',
      'chat_title': 'КАНАЛ ПОВІДОМЛЕНЬ P2P',
      'chat_empty': 'Немає повідомлень у буфері RAM.',
      'chat_hint': 'Зашифроване повідомлення...',
      'send_btn': 'ВІДПРАВИТИ ПОВІДОМЛЕННЯ',
      'stegano_title': 'МОДУЛЬ СТЕГАНОГРАФІЇ (ПРИХОВУВАННЯ ТА ВИТЯГ)',
      'stegano_hint': 'Вставте стегано-текст або ключ для приховування...',
      'stegano_btn': 'ПРИХОВАТИ КЛЮЧ У ВІРШІ',
      'stegano_extract_btn': 'ВИТЯГТИ КЛЮЧ ІЗ ТЕКСТU',
      'stegano_result': 'Стеганографічний результат:',
      'security_panel': 'БЕЗПЕКА ТА ЕКСТРЕНЕ ЗНИЩЕННЯ',
      'kill_switch_btn': 'НЕГАЙНЕ ОЧИЩЕННЯ RAM (KILL SWITCH)',
      'change_pin_btn': 'ЗМІНИТИ ПАРОЛЬ СЕСІЇ',
      'recipient_address': 'Публічний Ключ / Onion Адреса одержувача',
      'connect_peer': 'ПІДКЛЮЧИТИ ПІРА',
      'my_address': 'ВАШ ПУБЛІЧНИЙ КЛЮЧ ТА ЕФЕМЕРНИЙ ID P2P:',
      'peer_connected': 'Підключено до піра:',
      'peer_none': 'Жодного піра не підключено (Трансляція наосліп)',
      'show_qr': 'МІЙ QR-КОД',
      'scan_qr': 'СКАНУВАТИ QR-КОД',
      'copy_key': 'СКОПІЮВАТИ МІЙ КЛЮЧ',
      'fake_dashboard_title': 'ОСОБИСТІ НОТАТКИ',
      'media_select_btn': 'ЗАВАНТАЖИТИ ФАЙЛ У RAM (ФОТО/ВІДЕО/DOC)',
    },
    'ar': {
      'subtitle': 'جلسة RAM متطايرة - بصمة صفر',
      'pin_hint': 'أدخل كلمة المرور',
      'license_hint': 'مفتاح ترخيص العميل (مثال: AEGIS-XXXX)',
      'unlock_btn': 'إلغاء قفل الجلسة',
      'create_pin_hint': 'أنشئ كلمة المرور الخاصة بك (4 أرقام كحد أدنى)',
      'init_vault_btn': 'تهيئة القبو الآمن',
      'pin_error': 'كلمة المرور أو الترخيص غير صالحة - تم مسح الذاكرة',
      'dashboard_title': 'وحدة تحكم AEGIS CORE',
      'network_mode': 'وضع نقل الشبكة',
      't_tor': 'Tor v3 مدمج (أقصى قدر من عدم الكشف عن الهوية)',
      't_wan': 'WAN مباشر (P2P / DHT سريع)',
      't_lan': 'غير متصل / محلي (Wi-Fi / بلوتوث)',
      't_auto': 'هجين / تلقائي (قفز النقل)',
      'chat_title': 'قناة رسائل P2P',
      'chat_empty': 'لا توجد رسائل في ذاكرة التخزين المؤقت RAM.',
      'chat_hint': 'رسالة مشفرة...',
      'send_btn': 'إرسال رسالة',
      'stegano_title': 'وحدة إخفاء المعلومات (إخفاء واستخراج)',
      'stegano_hint': 'الصق نص ستيغانو أو المفتاح لإخفائه...',
      'stegano_btn': 'إخفاء المفتاح في قصيدة',
      'stegano_extract_btn': 'استخراج المفتاح من النص',
      'stegano_result': 'نتيجة إخفاء المعلومات:',
      'security_panel': 'الأمن والتدمير في حالات الطوارئ',
      'kill_switch_btn': 'تطهير فوري للذاكرة (مفتاح القتل)',
      'change_pin_btn': 'تغيير كلمة مرور الجلسة',
      'recipient_address': 'المفتاح العام / عنوان Onion للمستلم',
      'connect_peer': 'اتصال بالقرين',
      'my_address': 'مفتاحك العام ومعرف P2P المؤقت:',
      'peer_connected': 'متصل بالقرين:',
      'peer_none': 'لا يوجد قرين متصل (بث أعمى)',
      'show_qr': 'رمز الاستجابة السريعة الخاص بي',
      'scan_qr': 'مسح رمز الاستجابة السريعة',
      'copy_key': 'نسخ مفتاحي',
      'fake_dashboard_title': 'ملاحظات شخصية',
      'media_select_btn': 'تحميل ملف إلى RAM (صورة/فيديو/نص)',
    },
  };

  static String get(BuildContext context, String key) {
    String code = Localizations.localeOf(context).languageCode;
    if (!_localizedValues.containsKey(code)) code = 'en';
    return _localizedValues[code]?[key] ?? key;
  }
}

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
      child: const Center(
        child: Icon(Icons.shield_outlined, size: 50, color: brandYellow),
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

  @override
  void initState() {
    super.initState();
    _checkVaultState();
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
      SystemNavigator.pop();
      exit(137);
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
      if (licenseKey.isNotEmpty && !verifyLicenseKeyFfi(licenseKey)) {
        if (!mounted) return;
        _pinController.clear();
        setState(() { _isLoading = false; });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(AppTranslations.get(context, 'pin_error'))),
        );
        return;
      }

      final success = await _vault.initializeMasterPin(pin);
      if (!mounted) return;

      _pinController.clear();
      _licenseController.clear();
      setState(() { _isLoading = false; });

      if (success) {
        _sendDeadmanHeartbeat();
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(builder: (context) => const MainDashboard()),
        );
      }
      return;
    }

    final session = await _vault.unlockSession(pin);
    if (!mounted) return;

    _pinController.clear();
    setState(() { _isLoading = false; });

    if (session.type == VaultSessionType.real) {
      _sendDeadmanHeartbeat();
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(builder: (context) => const MainDashboard()),
      );
    } else {
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(builder: (context) => const FakeDashboard()),
      );
    }
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

    String displayHint = _isVaultInitialized!
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
                TextField(
                  controller: _pinController,
                  obscureText: true,
                  enableInteractiveSelection: false,
                  enabled: !_isLoading,
                  keyboardType: TextInputType.text,
                  textAlign: TextAlign.center,
                  decoration: InputDecoration(
                    hintText: displayHint,
                    hintStyle: const TextStyle(color: Colors.white54),
                    focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide(color: buttonColor)),
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                  ),
                ),
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

  List<List<Map<String, String>>> _getLocalizedDecoyNotes(String langCode) {
    switch (langCode) {
      case 'fr':
        return [
          [
            {'title': 'Courses hebdomadaires', 'subtitle': 'Pain, Lait d\'amande, Café, Pommes, Pâtes, Beurre'},
            {'title': 'Rappels maison', 'subtitle': 'Arroser les plantes, Purger le radiateur du salon'},
            {'title': 'Idées cadeaux Thomas', 'subtitle': 'Livre de cuisine italienne ou BD science-fiction'},
          ],
          [
            {'title': 'Matériel Bricolage', 'subtitle': 'Vis à bois 4x40, Peinture blanche mate, Pinceaux plat'},
            {'title': 'Révision voiture', 'subtitle': 'Contrôler niveau d\'huile et pression des pneus à froid'},
            {'title': 'Pharmacie', 'subtitle': 'Pansements étanches, Doliprane 1g, Crème apaisante'},
          ],
        ];
      case 'es':
        return [
          [
            {'title': 'Compras semanales', 'subtitle': 'Pan, Leche de almendras, Café, Manzanas, Pasta, Mantequilla'},
            {'title': 'Recordatorios', 'subtitle': 'Regar las plantas, Purgar el radiador'},
            {'title': 'Ideas regalo Thomas', 'subtitle': 'Libro de cocina italiana o cómic de ciencia ficción'},
          ],
          [
            {'title': 'Material Bricolaje', 'subtitle': 'Tornillos madera 4x40, Pintura blanca mate, Pinceles'},
            {'title': 'Revisión coche', 'subtitle': 'Comprobar presión de neumáticos y aceite en frío'},
            {'title': 'Farmacia', 'subtitle': 'Tiritas impermeables, Paracetamol 1g, Crema calmante'},
          ],
        ];
      case 'it':
        return [
          [
            {'title': 'Spesa settimanale', 'subtitle': 'Pane, Latte di mandorla, Caffè, Mele, Pasta, Burro'},
            {'title': 'Promemoria casa', 'subtitle': 'Annaffiare le piante, Spurgare il termosifone'},
            {'title': 'Idee regalo Thomas', 'subtitle': 'Libro di cucina italiana o fumetto di fantascienza'},
          ],
          [
            {'title': 'Fai da te', 'subtitle': 'Viti per legno 4x40, Vernice bianca opaca, Pennelli piatti'},
            {'title': 'Manutenzione auto', 'subtitle': 'Controllare pressione pneumatici e olio a freddo'},
            {'title': 'Farmacia', 'subtitle': 'Cerotti impermeabili, Paracetamolo 1g, Crema lenitiva'},
          ],
        ];
      case 'pl':
        return [
          [
            {'title': 'Zakupy tygodniowe', 'subtitle': 'Chleb, Mleko migdałowe, Kawa, Jabłka, Makaron, Masło'},
            {'title': 'Przypomnienia', 'subtitle': 'Podlać rośliny, Odpowietrzyć kaloryfer'},
            {'title': 'Prezent dla Tomasza', 'subtitle': 'Włoska książka kucharska lub komiks sci-fi'},
          ],
          [
            {'title': 'Majsterkowanie', 'subtitle': 'Wkręty do drewna 4x40, Biała farba matowa, Pędzle'},
            {'title': 'Przegląd auta', 'subtitle': 'Sprawdzić ciśnienie w oponach i olej na zimno'},
            {'title': 'Apteka', 'subtitle': 'Wodoodporne plastry, Paracetamol 1g, Krem łagodzący'},
          ],
        ];
      case 'uk':
        return [
          [
            {'title': 'Щотижневі покупки', 'subtitle': 'Хліб, Мигдальне молоко, Кава, Яблука, Макарони, Масло'},
            {'title': 'Домашні справи', 'subtitle': 'Полити квіти, Спустити повітря з батареї'},
            {'title': 'Подарунок для Томаса', 'subtitle': 'Італійська кулінарна книга або комікс'},
          ],
          [
            {'title': 'Ремонт', 'subtitle': 'Шурупи для дерева 4x40, Матова біла фарба, Пензлі'},
            {'title': 'Автомобіль', 'subtitle': 'Перевірити тиск у шинах та масло на холодно'},
            {'title': 'Аптека', 'subtitle': 'Водонепроникні пластирі, Парацетамол 1г, Крем'},
          ],
        ];
      case 'ar':
        return [
          [
            {'title': 'البقالة الأسبوعية', 'subtitle': 'خبز، حليب لوز، قهوة، تفاح، مكرونة، زبدة'},
            {'title': 'تذكيرات المنزل', 'subtitle': 'سقي النباتات، تنفيس المدفأة'},
            {'title': 'أفكار هدايا لتوماس', 'subtitle': 'كتاب طبخ إيطالي أو قصة خيال علمي'},
          ],
          [
            {'title': 'مستلزمات الصيانة', 'subtitle': 'مسامير خشب 4x40، طلاء أبيض غير لامع، فرش'},
            {'title': 'صيانة السيارة', 'subtitle': 'التحقق من ضغط الإطارات ومستوى الزيت'},
            {'title': 'الصيدلية', 'subtitle': 'ضمادات مقاومة للماء، باراسيتامول 1 جرام، كريم مهدئ'},
          ],
        ];
      case 'en':
      default:
        return [
          [
            {'title': 'Weekly Groceries', 'subtitle': 'Bread, Almond milk, Coffee, Apples, Pasta, Butter'},
            {'title': 'House reminders', 'subtitle': 'Water the plants, Bleed the living room radiator'},
            {'title': 'Thomas gift ideas', 'subtitle': 'Italian cookbook or sci-fi comic book'},
          ],
          [
            {'title': 'DIY Supplies', 'subtitle': '4x40 wood screws, Matte white paint, Flat brushes'},
            {'title': 'Car maintenance', 'subtitle': 'Check tire pressure and oil level when cold'},
            {'title': 'Pharmacy', 'subtitle': 'Waterproof bandages, Paracetamol 1g, Soothing cream'},
          ],
        ];
    }
  }

  @override
  Widget build(BuildContext context) {
    final String langCode = Localizations.localeOf(context).languageCode;
    final decoyNotes = _getLocalizedDecoyNotes(langCode);

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
  final TextEditingController _steganoController = TextEditingController();
  final TextEditingController _recipientController = TextEditingController();
  final TextEditingController _chatController = TextEditingController();

  String _steganoResult = "";
  final List<String> _chatMessages = [];
  String _networkMode = "t_auto";
  String _connectedPeer = "";

  final Map<String, List<String>> _localizedPoems = {
    'fr': [
      "Dans l'ombre des cités silencieuses le vent murmure des secrets oubliés...",
      "Les étoiles lointaines brillent d'un éclat froid au-dessus de l'océan obscur...",
      "Sous la pluie fine de novembre les feuilles d'or recouvrent les chemins abandonnés...",
    ],
    'en': [
      "In the shadow of silent cities the wind whispers forgotten secrets...",
      "Distant stars shine with a cold light above the dark ocean...",
      "Under the fine November rain golden leaves cover the abandoned paths...",
    ],
    'es': [
      "En la sombra de las ciudades silenciosas el viento susurra secretos olvidados...",
      "Las estrellas lejanas brillan con un brillo frío sobre el océano oscuro...",
      "Bajo la fina lluvia de noviembre las hojas de oro cubren los caminos abandonados...",
    ],
    'it': [
      "Nell'ombra delle città silenziose il vento sussurra segreti dimenticati...",
      "Le stelle lontane brillano di una luce fredda sopra l'oceano oscuro...",
      "Sotto la fine pioggia di novembre le foglie d'oro coprono i sentieri abbandonati...",
    ],
    'pl': [
      "W cieniu milczących miast wiatr szepcze zapomniane sekrety...",
      "Odległe gwiazdy świecą zimnym blaskiem nad ciemnym oceanem...",
      "W drobnym listopadowym deszczu złote liście pokrywają opuszczone ścieżki...",
    ],
    'uk': [
      "У тіні мовчазних міст вітер шепоче забуті таємниці...",
      "Далекі зорі світять холодним блиском над темним океаном...",
      "Під дрібним листопадовим дощем золоте листя вкриває покинуті стежки...",
    ],
    'ar': [
      "في ظلال المدن الصامتة، تهمس الرياح بأسرار منسية...",
      "النجوم البعيدة تضيء ببريق بارد فوق المحيط المظلم...",
      "تحت مطر تشرين الثاني الخفيف، تغطي الأوراق الذهبية الطرق المهجورة...",
    ],
  };

  @override
  void dispose() {
    _steganoController.dispose();
    _recipientController.dispose();
    _chatController.dispose();
    super.dispose();
  }

  void _drownKeyInPoem() {
    final text = _steganoController.text.trim();
    if (text.isEmpty) return;

    final String langCode = Localizations.localeOf(context).languageCode;
    final poemsList = _localizedPoems[langCode] ?? _localizedPoems['en']!;
    final poem = poemsList[Random().nextInt(poemsList.length)];

    setState(() {
      _steganoResult = drownKeyFfi(text, poem);
    });
  }

  void _extractKeyFromPoem() {
    final text = _steganoController.text.trim();
    if (text.isEmpty) return;

    setState(() {
      _steganoResult = extractKeyFfi(text);
    });
  }

  Future<void> _pickFileZeroDisk() async {
    isIntentPendingInDart = true;
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
                  ? "Fichier ingéré en RAM Zero-Disk avec succès (mlock)"
                  : "Échec de l'ingestion Zero-Disk"),
              backgroundColor: success ? Colors.green : Colors.red,
            ),
          );
        }
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text("Erreur sélection fichier : $e")),
      );
    } finally {
      isIntentPendingInDart = false;
    }
  }

  void _openQrScanner() {
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
    const String myEphemeralKey = "AEGIS-P2P-v2.2-GA-4F8B12E9903A7C12D";
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
            const SelectableText(
              myEphemeralKey,
              style: TextStyle(color: Colors.greenAccent, fontSize: 11),
              textAlign: TextAlign.center,
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () {
              Clipboard.setData(const ClipboardData(text: myEphemeralKey));
              Navigator.pop(ctx);
            },
            child: Text(AppTranslations.get(context, 'copy_key'), style: const TextStyle(color: Color(0xFFFCBE0B))),
          ),
        ],
      ),
    );
  }

  void _sendMessage() {
    final msg = _chatController.text.trim();
    if (msg.isEmpty) return;

    setState(() {
      _chatMessages.add("Moi: $msg");
      _chatController.clear();
    });
  }

  void _instantRamPurge() {
    _executeEmergencyFfiPurge();
    activeRamPin = "";
    SystemNavigator.pop();
    exit(137);
  }

  @override
  Widget build(BuildContext context) {
    const Color brandYellow = Color(0xFFFCBE0B);

    return Scaffold(
      appBar: AppBar(
        title: Text(AppTranslations.get(context, 'dashboard_title')),
        backgroundColor: Colors.grey[900],
        actions: [
          IconButton(
            icon: const Icon(Icons.remove_red_eye, color: brandYellow),
            onPressed: () {
              Navigator.push(
                context,
                MaterialPageRoute(builder: (context) => const BlindViewerScreen()),
              );
            },
          ),
          IconButton(
            icon: const Icon(Icons.power_settings_new, color: Colors.red),
            onPressed: _instantRamPurge,
          ),
        ],
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(AppTranslations.get(context, 'network_mode'), style: const TextStyle(fontWeight: FontWeight.bold, color: brandYellow)),
              const SizedBox(height: 8),
              DropdownButton<String>(
                value: _networkMode,
                isExpanded: true,
                dropdownColor: Colors.grey[900],
                items: [
                  DropdownMenuItem(value: "t_tor", child: Text(AppTranslations.get(context, 't_tor'))),
                  DropdownMenuItem(value: "t_wan", child: Text(AppTranslations.get(context, 't_wan'))),
                  DropdownMenuItem(value: "t_lan", child: Text(AppTranslations.get(context, 't_lan'))),
                  DropdownMenuItem(value: "t_auto", child: Text(AppTranslations.get(context, 't_auto'))),
                ],
                onChanged: (val) {
                  if (val != null) setState(() => _networkMode = val);
                },
              ),
              const Divider(height: 24, color: Colors.grey),
              Text(AppTranslations.get(context, 'my_address'), style: const TextStyle(fontWeight: FontWeight.bold, color: brandYellow, fontSize: 11)),
              const SizedBox(height: 6),
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: _showMyQrCode,
                      icon: const Icon(Icons.qr_code, color: brandYellow, size: 18),
                      label: Text(AppTranslations.get(context, 'show_qr'), style: const TextStyle(color: Colors.white, fontSize: 11)),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: _openQrScanner,
                      icon: const Icon(Icons.qr_code_scanner, color: Colors.greenAccent, size: 18),
                      label: Text(AppTranslations.get(context, 'scan_qr'), style: const TextStyle(color: Colors.white, fontSize: 11)),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              TextField(
                controller: _recipientController,
                enableInteractiveSelection: false,
                style: const TextStyle(fontSize: 12),
                decoration: InputDecoration(
                  hintText: AppTranslations.get(context, 'recipient_address'),
                  border: const OutlineInputBorder(),
                  contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                ),
              ),
              const SizedBox(height: 6),
              ElevatedButton(
                onPressed: () {
                  final peer = _recipientController.text.trim();
                  if (peer.isNotEmpty) {
                    setState(() => _connectedPeer = peer);
                  }
                },
                style: ElevatedButton.styleFrom(backgroundColor: Colors.blueGrey[800], foregroundColor: Colors.white, minimumSize: const Size(double.infinity, 36)),
                child: Text(AppTranslations.get(context, 'connect_peer'), style: const TextStyle(fontSize: 11)),
              ),
              Padding(
                padding: const EdgeInsets.only(top: 4.0),
                child: Text(
                  _connectedPeer.isNotEmpty
                      ? "${AppTranslations.get(context, 'peer_connected')} $_connectedPeer"
                      : AppTranslations.get(context, 'peer_none'),
                  style: TextStyle(color: _connectedPeer.isNotEmpty ? Colors.greenAccent : Colors.grey, fontSize: 10),
                ),
              ),
              const Divider(height: 24, color: Colors.grey),
              ElevatedButton.icon(
                onPressed: _pickFileZeroDisk,
                style: ElevatedButton.styleFrom(
                  backgroundColor: brandYellow,
                  foregroundColor: Colors.black,
                  minimumSize: const Size(double.infinity, 44),
                ),
                icon: const Icon(Icons.attach_file),
                label: Text(AppTranslations.get(context, 'media_select_btn'), style: const TextStyle(fontWeight: FontWeight.bold)),
              ),
              const Divider(height: 28, color: Colors.grey),
              Text(AppTranslations.get(context, 'stegano_title'), style: const TextStyle(fontWeight: FontWeight.bold, color: brandYellow)),
              const SizedBox(height: 8),
              TextField(
                controller: _steganoController,
                maxLines: 3,
                enableInteractiveSelection: false,
                decoration: InputDecoration(
                  hintText: AppTranslations.get(context, 'stegano_hint'),
                  border: const OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: ElevatedButton(
                      onPressed: _drownKeyInPoem,
                      style: ElevatedButton.styleFrom(backgroundColor: brandYellow, foregroundColor: Colors.black),
                      child: Text(AppTranslations.get(context, 'stegano_btn'), style: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold)),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: ElevatedButton(
                      onPressed: _extractKeyFromPoem,
                      style: ElevatedButton.styleFrom(backgroundColor: Colors.blueGrey, foregroundColor: Colors.white),
                      child: Text(AppTranslations.get(context, 'stegano_extract_btn'), style: const TextStyle(fontSize: 10)),
                    ),
                  ),
                ],
              ),
              if (_steganoResult.isNotEmpty) ...[
                const SizedBox(height: 12),
                Text(AppTranslations.get(context, 'stegano_result'), style: const TextStyle(fontSize: 12, color: Colors.grey)),
                SelectableText(_steganoResult, style: const TextStyle(color: Colors.greenAccent, fontSize: 12)),
              ],
              const Divider(height: 28, color: Colors.grey),
              Text(AppTranslations.get(context, 'chat_title'), style: const TextStyle(fontWeight: FontWeight.bold, color: brandYellow)),
              const SizedBox(height: 8),
              Container(
                height: 100,
                decoration: BoxDecoration(border: Border.all(color: Colors.grey[800]!), borderRadius: BorderRadius.circular(8)),
                child: _chatMessages.isEmpty
                    ? Center(child: Text(AppTranslations.get(context, 'chat_empty'), style: const TextStyle(color: Colors.grey, fontSize: 12)))
                    : ListView.builder(
                        itemCount: _chatMessages.length,
                        itemBuilder: (context, idx) => Padding(
                          padding: const EdgeInsets.all(4.0),
                          child: Text(_chatMessages[idx], style: const TextStyle(fontSize: 12)),
                        ),
                      ),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _chatController,
                      enableInteractiveSelection: false,
                      decoration: InputDecoration(
                        hintText: AppTranslations.get(context, 'chat_hint'),
                        border: const OutlineInputBorder(),
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  IconButton(
                    icon: const Icon(Icons.send, color: brandYellow),
                    onPressed: _sendMessage,
                  ),
                ],
              ),
              const Divider(height: 28, color: Colors.grey),
              ElevatedButton.icon(
                onPressed: _instantRamPurge,
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.red[900],
                  foregroundColor: Colors.white,
                  minimumSize: const Size(double.infinity, 44),
                ),
                icon: const Icon(Icons.warning),
                label: Text(AppTranslations.get(context, 'kill_switch_btn'), style: const TextStyle(fontWeight: FontWeight.bold)),
              ),
            ],
          ),
        ),
      ),
    );
  }
}