import 'dart:async';
import 'dart:convert';
import 'dart:ffi' hide Size;
import 'dart:io';
import 'dart:math';
import 'package:ffi/ffi.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_windowmanager_plus/flutter_windowmanager_plus.dart';
import 'package:path_provider/path_provider.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'views/blind_viewer.dart';

import 'models/session_vault.dart';

String activeRamPin = "";

/// Vérifie l'empreinte de signature du binaire hôte auprès du noyau Rust au démarrage
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

// Fonction d'extraction tactique de Snowflake
Future<void> deploySnowflake() async {
  try {
    final directory = await getApplicationDocumentsDirectory();
    final snowflakePath = '${directory.path}/snowflake-client';
    final snowflakeFile = File(snowflakePath);

    if (!await snowflakeFile.exists()) {
      debugPrint("Extraction de Snowflake en cours...");
      final byteData = await rootBundle.load('assets/bin/snowflake-client');
      await snowflakeFile.writeAsBytes(byteData.buffer.asUint8List(byteData.offsetInBytes, byteData.lengthInBytes));
    }

    if (Platform.isLinux || Platform.isMacOS) {
      final result = await Process.run('chmod', ['+x', snowflakePath]);
      if (result.exitCode == 0) {
        debugPrint("Opération propre : Snowflake est armé et prêt à l'exécution !");
        debugPrint("Chemin absolu : $snowflakePath");
      } else {
        debugPrint("Erreur de permission : ${result.stderr}");
      }
    }
  } catch (e) {
    debugPrint("Échec du déploiement : $e");
  }
}

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  if (Platform.isAndroid) {
    const currentApkSha256 = "94e3dfbcac6e9dfccbafb07320728c468dbce38ec3f0e9501ee9703fe06a9ff7";
    verifyApkSignatureOrBurn(currentApkSha256);
  }

  try {
    if (Platform.isAndroid) {
      await FlutterWindowManagerPlus.addFlags(FlutterWindowManagerPlus.FLAG_SECURE);
    }
  } catch (e) {
    debugPrint("Erreur lors de l'activation de FLAG_SECURE : $e");
  }

  await deploySnowflake();

  SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
  runApp(const AegisApp());
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

class _AegisAppState extends State<AegisApp> with WidgetsBindingObserver {
  Locale? _locale;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // COUPE-CIRCUIT : Extinction immédiate (exit 137) au moindre changement d'état / perte de focus
    if (state == AppLifecycleState.inactive ||
        state == AppLifecycleState.paused ||
        state == AppLifecycleState.detached) {
      exit(137);
    }
  }

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
    _inactivityTimer?.cancel();
    _inactivityTimer = Timer(const Duration(minutes: 3), () {
      activeRamPin = "";
      SystemNavigator.pop();
      exit(137);
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
      'unlock_btn': 'DÉVERROUILLER LA SESSION',
      'create_pin_hint': 'CRÉEZ VOTRE MOT DE PASSE (MIN 4 CHIFFRES)',
      'init_vault_btn': 'INITIALISER LE COFFRE SÉCURISÉ',
      'pin_error': 'Mot de Passe Invalide - Purge Mémoire',
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
      'my_address': 'VOTRE CLÉ PUBLIQUE & ID P2P ÉPHÉMÈRE :',
      'peer_connected': 'Connecté au pair :',
      'peer_none': 'Aucun correspondant connecté (Bouteille à la mer)',
      'show_qr': 'MON QR CODE',
      'scan_qr': 'SCANNER UN QR CODE',
      'copy_key': 'COPIER MA CLÉ',
      'fake_dashboard_title': 'NOTES PERSONNELLES',
      'heavy_files_title': 'INGESTION FICHIERS LOURDS & BLIND VIEWER',
      'heavy_files_desc': 'Dépuration EXIF/GPS, Padding RAM & Rendu VRAM Zero-Disk',
      'open_blind_viewer': 'OUVRIR LE BLIND VIEWER (ZERO-DISK)',
    },
    'en': {
      'subtitle': 'Volatile RAM Session - Zero Trace',
      'pin_hint': 'Enter Password',
      'unlock_btn': 'UNLOCK SESSION',
      'create_pin_hint': 'CREATE YOUR PASSWORD (MIN 4 DIGITS)',
      'init_vault_btn': 'INITIALIZE SECURE VAULT',
      'pin_error': 'Invalid Password - Memory Purged',
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
      'scan_qr': 'SCAN QR CODE',
      'copy_key': 'COPY MY KEY',
      'fake_dashboard_title': 'PERSONAL NOTES',
      'heavy_files_title': 'HEAVY FILE INGESTION & BLIND VIEWER',
      'heavy_files_desc': 'EXIF/GPS Stripping, RAM Padding & VRAM Zero-Disk Rendering',
      'open_blind_viewer': 'OPEN BLIND VIEWER (ZERO-DISK)',
    },
    'es': {
      'subtitle': 'Sesión RAM Volátil - Huella Cero',
      'pin_hint': 'Ingrese su Contraseña',
      'unlock_btn': 'DESBLOQUEAR SESIÓN',
      'create_pin_hint': 'CREE SU CONTRASEÑA (MÍN 4 DÍGITOS)',
      'init_vault_btn': 'INICIALIZAR BÓVEDA SEGURA',
      'pin_error': 'Contraseña Inválida - Memoria Purgada',
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
      'heavy_files_title': 'INGESTIÓN DE ARCHIVOS PESADOS Y BLIND VIEWER',
      'heavy_files_desc': 'Depuración EXIF/GPS, Padding RAM y Renders VRAM Zero-Disk',
      'open_blind_viewer': 'ABRIR BLIND VIEWER (ZERO-DISK)',
    },
    'it': {
      'subtitle': 'Sessione RAM Volatile - Traccia Zero',
      'pin_hint': 'Inserisci la Password',
      'unlock_btn': 'SBLOCCA SESSIONE',
      'create_pin_hint': 'CREA LA TUA PASSWORD (MIN 4 CIFRE)',
      'init_vault_btn': 'INIZIALIZZA CASSAFORTE SICURA',
      'pin_error': 'Password non valida - Memoria Purgata',
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
      'heavy_files_title': 'INGESTIONE FILE PESANTI E BLIND VIEWER',
      'heavy_files_desc': 'Pulizia EXIF/GPS, Padding RAM e Rendering VRAM Zero-Disk',
      'open_blind_viewer': 'APRI BLIND VIEWER (ZERO-DISK)',
    },
    'pl': {
      'subtitle': 'Ulotna Sesja RAM - Zerowy Ślad',
      'pin_hint': 'Wprowadź Hasło',
      'unlock_btn': 'ODBLOKUJ SESJĘ',
      'create_pin_hint': 'UTWÓRZ HASŁO (MIN 4 CYFRY)',
      'init_vault_btn': 'INICJALIZUJ BEZPIECZNY SKARBIEC',
      'pin_error': 'Nieprawidłowe Hasło - Pamięć Oczyszczona',
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
      'heavy_files_title': 'INSYGNIACJA CIĘŻKICH PLIKÓW I BLIND VIEWER',
      'heavy_files_desc': 'Czyszczenie EXIF/GPS, Padding RAM i Renderowanie VRAM Zero-Disk',
      'open_blind_viewer': 'OTWÓRZ BLIND VIEWER (ZERO-DISK)',
    },
    'uk': {
      'subtitle': 'Летка Сесія RAM - Нульовий Слід',
      'pin_hint': 'Введіть Пароль',
      'unlock_btn': 'РОЗБЛОКУВАТИ СЕСІЮ',
      'create_pin_hint': 'СТВОРІТЬ ПАРОЛЬ (МІН. 4 ЦИФРИ)',
      'init_vault_btn': 'ІНІЦІАЛІЗУВАТИ БЕЗПЕЧНЕ СХОВИЩЕ',
      'pin_error': 'Недійсний Пароль - Пам\'ять Очищено',
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
      'heavy_files_title': 'ІМПОРТ ВАЖКИХ ФАЙЛІВ ТА BLIND VIEWER',
      'heavy_files_desc': 'Очищення EXIF/GPS, Падинг RAM та Рендеринг VRAM Zero-Disk',
      'open_blind_viewer': 'ВІДКРИТИ BLIND VIEWER (ZERO-DISK)',
    },
    'ar': {
      'subtitle': 'جلسة RAM متطايرة - بصمة صفر',
      'pin_hint': 'أدخل كلمة المرور',
      'unlock_btn': 'إلغاء قفل الجلسة',
      'create_pin_hint': 'أنشئ كلمة المرور الخاصة بك (4 أرقام كحد أدنى)',
      'init_vault_btn': 'تهيئة القبو الآمن',
      'pin_error': 'كلمة المرور غير صالحة - تم مسح الذاكرة',
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
      'heavy_files_title': 'استيعاب الملفات الثقيلة و BLIND VIEWER',
      'heavy_files_desc': 'تطهير EXIF/GPS ، حشو RAM وتقديم VRAM Zero-Disk',
      'open_blind_viewer': 'افتح BLIND VIEWER (ZERO-DISK)',
    },
  };

  static String get(BuildContext context, String key) {
    String code = Localizations.localeOf(context).languageCode;
    if (!_localizedValues.containsKey(code)) code = 'en';
    return _localizedValues[code]?[key] ?? key;
  }
}

class LockScreen extends StatefulWidget {
  const LockScreen({super.key});

  @override
  State<LockScreen> createState() => _LockScreenState();
}

class _LockScreenState extends State<LockScreen> {
  final TextEditingController _pinController = TextEditingController();
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
      debugPrint("Échec de l'appel FFI Silent Burn, secours local : $e");
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
    } catch (e) {
      debugPrint("Échec d'envoi du Heartbeat DeadMan : $e");
    }
  }

  void _unlock() async {
    final pin = _pinController.text.trim();
    if (pin.isEmpty) return;

    if (pin == "9999") {
      _pinController.clear();
      _triggerSilentBurn();
      return;
    }

    setState(() { _isLoading = true; });

    if (_isVaultInitialized == false) {
      final success = await _vault.initializeMasterPin(pin);
      if (!mounted) return;
      _pinController.clear();
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
                Image.asset(
                  'assets/logo.png',
                  height: 130,
                  fit: BoxFit.contain,
                  errorBuilder: (context, error, stackTrace) => const Text(
                    'ARES / AEGIS',
                    style: TextStyle(fontSize: 28, fontWeight: FontWeight.bold, color: brandYellow),
                  ),
                ),
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
                TextField(
                  controller: _pinController,
                  obscureText: true,
                  enableInteractiveSelection: false, 
                  enabled: !_isLoading,
                  keyboardType: TextInputType.text,
                  textAlign: TextAlign.center,
                  decoration: InputDecoration(
                    hintText: displayHint,
                    hintStyle: TextStyle(color: _isVaultInitialized! ? Colors.white54 : Colors.black87),
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
            {'title': 'Gift ideas for Thomas', 'subtitle': 'Italian cookbook or Sci-Fi comic book'},
          ],
          [
            {'title': 'DIY Supplies', 'subtitle': '4x40 wood screws, Matte white paint, Flat brushes'},
            {'title': 'Car maintenance', 'subtitle': 'Check cold tire pressure and oil level'},
            {'title': 'Pharmacy', 'subtitle': 'Waterproof bandages, Paracetamol 1g, Soothing cream'},
          ],
        ];
    }
  }

  @override
  Widget build(BuildContext context) {
    final langCode = Localizations.localeOf(context).languageCode;
    final decoyNotes = _getLocalizedDecoyNotes(langCode);
    final currentList = decoyNotes[Random().nextInt(decoyNotes.length)];

    return Scaffold(
      appBar: AppBar(
        title: Text(AppTranslations.get(context, 'fake_dashboard_title')),
        actions: [
          IconButton(
            icon: const Icon(Icons.close),
            onPressed: () {
              SystemNavigator.pop();
              exit(137);
            },
          )
        ],
      ),
      body: ListView.builder(
        padding: const EdgeInsets.all(16),
        itemCount: currentList.length,
        itemBuilder: (context, index) {
          final item = currentList[index];
          return Card(
            margin: const EdgeInsets.only(bottom: 12),
            child: ListTile(
              leading: const Icon(Icons.check_box_outline_blank, color: Colors.grey),
              title: Text(item['title']!, style: const TextStyle(fontWeight: FontWeight.bold)),
              subtitle: Text(item['subtitle']!),
            ),
          );
        },
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
  static const Color brandYellow = Color(0xFFFCBE0B);

  String _selectedTransportKey = "t_tor";

  final TextEditingController _peerAddressController = TextEditingController();
  String _connectedPeer = "";

  final String _myPublicKey = "aegis_pk_8f9a2b7c4d1e9f0a2b4c6d8e1f3a5b7c9d0e2f4a6b8c";

  final TextEditingController _chatController = TextEditingController();
  final List<Map<String, dynamic>> _messages = [];

  final TextEditingController _steganoController = TextEditingController();
  String _steganoResult = "";

  @override
  void dispose() {
    _peerAddressController.dispose();
    _chatController.dispose();
    _steganoController.dispose();
    super.dispose();
  }

  void _openBlindViewer() {
    Navigator.of(context).push(
      MaterialPageRoute(builder: (context) => const BlindViewerScreen()),
    );
  }

  void _connectPeer() {
    final peer = _peerAddressController.text.trim();
    if (peer.isNotEmpty) {
      setState(() {
        _connectedPeer = peer;
      });
    }
  }

  void _showMyQrCodeDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: const Color(0xFF141416),
        title: Text(AppTranslations.get(context, 'show_qr'), style: const TextStyle(color: brandYellow, fontSize: 16)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(12)),
              child: Image.network(
                'https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=$_myPublicKey',
                height: 180,
                width: 180,
                fit: BoxFit.contain,
                errorBuilder: (context, error, stackTrace) => const Icon(Icons.qr_code, size: 150, color: Colors.black),
              ),
            ),
            const SizedBox(height: 12),
            SelectableText(_myPublicKey, style: const TextStyle(color: Colors.white70, fontSize: 10), textAlign: TextAlign.center),
          ],
        ),
        actions: [
          ElevatedButton(
            onPressed: () => Navigator.pop(context),
            style: ElevatedButton.styleFrom(backgroundColor: brandYellow, foregroundColor: Colors.black),
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }

  Future<void> _scanPeerQrCode() async {
    final String? scannedKey = await Navigator.push(
      context,
      MaterialPageRoute(builder: (context) => const QRScannerScreen()),
    );

    if (scannedKey != null && scannedKey.isNotEmpty) {
      final strictAegisFormat = RegExp(r'^aegis_pk_[a-f0-9]{48}$');

      if (strictAegisFormat.hasMatch(scannedKey)) {
        setState(() {
          _peerAddressController.text = scannedKey;
        });
        _connectPeer();
      } else {
        debugPrint("OPSEC WARNING : QR Code rejeté. Format non conforme.");
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text("Alerte Sécurité : Le QR Code scanné n'est pas une clé AEGIS valide."),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    }
  }

  void _showChangePinDialog() {
    final controller = TextEditingController();
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(AppTranslations.get(context, 'change_pin_btn')),
        content: TextField(
          controller: controller,
          obscureText: true,
          enableInteractiveSelection: false, 
          decoration: InputDecoration(hintText: AppTranslations.get(context, 'pin_hint')),
        ),
        actions: [
          TextButton(
            onPressed: () {
              controller.dispose();
              Navigator.pop(context);
            },
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () {
              if (controller.text.trim().isNotEmpty) {
                setState(() {
                  activeRamPin = controller.text.trim();
                });
                controller.dispose();
                Navigator.pop(context);
              }
            },
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }

  void _sendMessage() {
    final text = _chatController.text.trim();
    if (text.isEmpty) return;

    final destDisplay = _connectedPeer.isEmpty
        ? "Broadcast"
        : (_connectedPeer.length > 16 ? "${_connectedPeer.substring(0, 16)}..." : _connectedPeer);

    setState(() {
      _messages.add({
        'text': text,
        'isMe': true,
        'time': DateTime.now().toString().substring(11, 16),
        'dest': destDisplay,
      });
    });

    _chatController.clear();
  }

  void _triggerPanicPurge() {
    activeRamPin = "";
    _messages.clear();
    _chatController.clear();
    _steganoController.clear();
    SystemNavigator.pop();
    exit(137);
  }

  List<String> _getLocalizedPoems(String langCode) {
    switch (langCode) {
      case 'fr':
        return [
          "Sous le vieux chêne verdoyant, le vent murmure la nuit parmi les ombres célestes.",
          "Les sanglots longs des violons de l'automne blessent mon cœur d'une langueur monotone.",
          "Dans le silence absolu de la forêt claire, les étoiles scintillent au-dessus des cimes.",
          "Sur les vagues sombres de l'océan infini, le voilier glisse vers l'horizon lointain."
        ];
      case 'es':
        return [
          "Bajo el viejo roble verde, el viento susurra de noche entre las sombras celestiales.",
          "Los largos sollozos de los violines de otoño hieren mi corazón con monótona languidez.",
          "En el silencio absoluto del bosque claro, las estrellas brillan sobre las copas de los árboles.",
          "Sobre las oscuras olas del océano infinito, el velero se desliza hacia el horizonte lejano."
        ];
      case 'it':
        return [
          "Sotto la vecchia quercia verde, il vento sussurra di notte tra le ombre celesti.",
          "I lunghi singhiozzi dei violini d'autunno feriscono il mio cuore con un languore monotono.",
          "Nel silenzio assoluto della foresta chiara, le stelle brillano sopra le cime degli alberi.",
          "Sulle onde scure dell'oceano infinito, il veliero scivola verso l'orizzonte lontano."
        ];
      case 'pl':
        return [
          "Pod starym zielonym dębem wiatr szepcze nocą wśród niebiańskich cieni.",
          "Długie szlochy jesiennych skrzypiec ranią moje serce monotonną ociężałością.",
          "W absolutnej ciszy jasnego lasu gwiazdy migoczą nad koronami drzew.",
          "Na ciemnych falach nieskończonego oceanu żaglówka sunie ku odległemu horyzontowi."
        ];
      case 'uk':
        return [
          "Під старим зеленим дубом вітер шепоче вночі серед небесних тіней.",
          "Довгі ридання осінніх скрипок ранять моє серце монотонною млявістю.",
          "В абсолютній тиші світлого лісу зірки мерехтять над кронами дерев.",
          "На темних хвилях нескінченного океану вітрильник ковзає до далекого горизонту."
        ];
      case 'ar':
        return [
          "تحت شجرة البلوط الخضراء القديمة، يهمس الريح في الليل بين الظلال السماوية.",
          "تنهدات كمان الخريف الطويلة تجرح قلبي بضعف رتيب.",
          "في الصمت المطلق للغابة الصافية، تتلألأ النجوم فوق قمم الأشجار.",
          "على الأمواج المظلمة للمحيط اللامتناهي، ينزلق المراكب الشراعي نحو الأفق البعيد."
        ];
      case 'en':
      default:
        return [
          "Under the old green oak, the wind whispers at night among the celestial shadows.",
          "The long sobs of the violins of autumn wound my heart with a monotonous languor.",
          "In the absolute silence of the clear forest, the stars twinkle above the canopy.",
          "On the dark waves of the infinite ocean, the sailboat glides toward the distant horizon."
        ];
    }
  }

  @override
  Widget build(BuildContext context) {
    final peerDisplay = _connectedPeer.isEmpty
        ? AppTranslations.get(context, 'peer_none')
        : "${AppTranslations.get(context, 'peer_connected')} ${_connectedPeer.length > 20 ? '${_connectedPeer.substring(0, 20)}...' : _connectedPeer}";

    return Scaffold(
      appBar: AppBar(
        title: Text(AppTranslations.get(context, 'dashboard_title'), style: const TextStyle(color: brandYellow, fontWeight: FontWeight.bold, fontSize: 15)),
        actions: [
          IconButton(
            tooltip: "Blind Viewer (Zero-Disk)",
            icon: const Icon(Icons.folder_special, color: brandYellow),
            onPressed: _openBlindViewer,
          ),
          IconButton(
            icon: const Icon(Icons.power_settings_new, color: Colors.redAccent),
            onPressed: _triggerPanicPurge,
          )
        ],
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          physics: const BouncingScrollPhysics(),
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // CARTE D'ACTION : INGESTION FICHIERS LOURDS & BLIND VIEWER
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: brandYellow.withValues(alpha: 0.1),
                  border: Border.all(color: brandYellow, width: 1.5),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        const Icon(Icons.shield, color: brandYellow, size: 20),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            AppTranslations.get(context, 'heavy_files_title'),
                            style: const TextStyle(color: brandYellow, fontWeight: FontWeight.bold, fontSize: 12),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 6),
                    Text(
                      AppTranslations.get(context, 'heavy_files_desc'),
                      style: const TextStyle(color: Colors.white70, fontSize: 10),
                    ),
                    const SizedBox(height: 10),
                    ElevatedButton.icon(
                      style: ElevatedButton.styleFrom(
                        backgroundColor: brandYellow,
                        foregroundColor: Colors.black,
                        minimumSize: const Size(double.infinity, 38),
                      ),
                      onPressed: _openBlindViewer,
                      icon: const Icon(Icons.remove_red_eye, size: 16),
                      label: Text(
                        AppTranslations.get(context, 'open_blind_viewer'),
                        style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 11),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              Text(AppTranslations.get(context, 'my_address'), style: const TextStyle(color: Colors.grey, fontSize: 10, fontWeight: FontWeight.bold)),
              const SizedBox(height: 4),
              SelectableText(_myPublicKey, style: const TextStyle(color: brandYellow, fontWeight: FontWeight.bold, fontSize: 11)),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: ElevatedButton.icon(
                      onPressed: _showMyQrCodeDialog,
                      icon: const Icon(Icons.qr_code_2, size: 16),
                      label: Text(AppTranslations.get(context, 'show_qr'), style: const TextStyle(fontSize: 11)),
                      style: ElevatedButton.styleFrom(backgroundColor: brandYellow, foregroundColor: Colors.black),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: _scanPeerQrCode,
                      icon: const Icon(Icons.qr_code_scanner, size: 16, color: brandYellow),
                      label: Text(AppTranslations.get(context, 'scan_qr'), style: const TextStyle(color: brandYellow, fontSize: 11)),
                      style: OutlinedButton.styleFrom(side: const BorderSide(color: brandYellow)),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _peerAddressController,
                      decoration: InputDecoration(
                        hintText: AppTranslations.get(context, 'recipient_address'),
                        contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                        border: const OutlineInputBorder(),
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  ElevatedButton(
                    onPressed: _connectPeer,
                    style: ElevatedButton.styleFrom(backgroundColor: brandYellow, foregroundColor: Colors.black),
                    child: Text(AppTranslations.get(context, 'connect_peer')),
                  )
                ],
              ),
              const SizedBox(height: 4),
              Text(
                peerDisplay,
                style: TextStyle(color: _connectedPeer.isEmpty ? Colors.orangeAccent : Colors.greenAccent, fontSize: 11),
              ),
              const SizedBox(height: 16),
              Text(AppTranslations.get(context, 'network_mode'), style: const TextStyle(color: Colors.grey, fontSize: 11)),
              const SizedBox(height: 4),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 12),
                decoration: BoxDecoration(border: Border.all(color: brandYellow), borderRadius: BorderRadius.circular(8)),
                child: DropdownButtonHideUnderline(
                  child: DropdownButton<String>(
                    value: _selectedTransportKey,
                    isExpanded: true,
                    dropdownColor: const Color(0xFF141416),
                    items: ["t_tor", "t_wan", "t_lan", "t_auto"]
                        .map((key) => DropdownMenuItem(value: key, child: Text(AppTranslations.get(context, key))))
                        .toList(),
                    onChanged: (val) {
                      if (val != null) setState(() => _selectedTransportKey = val);
                    },
                  ),
                ),
              ),
              const SizedBox(height: 16),
              Text(AppTranslations.get(context, 'chat_title'), style: const TextStyle(color: brandYellow, fontSize: 13, fontWeight: FontWeight.bold)),
              const SizedBox(height: 8),
              Container(
                height: 170,
                decoration: BoxDecoration(
                  color: const Color(0xFF141416),
                  border: Border.all(color: const Color(0xFF222228)),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: _messages.isEmpty
                    ? Center(child: Text(AppTranslations.get(context, 'chat_empty'), style: const TextStyle(color: Colors.white38, fontSize: 12)))
                    : ListView.builder(
                        padding: const EdgeInsets.all(12),
                        itemCount: _messages.length,
                        itemBuilder: (context, index) {
                          final msg = _messages[index];
                          return Container(
                            margin: const EdgeInsets.only(bottom: 8),
                            padding: const EdgeInsets.all(10),
                            decoration: BoxDecoration(
                              color: brandYellow.withValues(alpha: 0.12),
                              border: Border.all(color: brandYellow),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text("À: ${msg['dest']}", style: const TextStyle(color: brandYellow, fontSize: 10, fontWeight: FontWeight.bold)),
                                const SizedBox(height: 4),
                                Text(msg['text'], style: const TextStyle(color: Colors.white, fontSize: 13)),
                                Align(
                                  alignment: Alignment.centerRight,
                                  child: Text(msg['time'], style: const TextStyle(color: Colors.white38, fontSize: 9)),
                                ),
                              ],
                            ),
                          );
                        },
                      ),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _chatController,
                      decoration: InputDecoration(
                        hintText: AppTranslations.get(context, 'chat_hint'),
                        contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
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
              const SizedBox(height: 20),
              Text(AppTranslations.get(context, 'stegano_title'), style: const TextStyle(color: Colors.grey, fontSize: 11, fontWeight: FontWeight.bold)),
              const SizedBox(height: 5),
              TextField(
                controller: _steganoController,
                maxLines: 2,
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
                      onPressed: () {
                        try {
                          final input = _steganoController.text.trim().isEmpty ? _myPublicKey : _steganoController.text.trim();

                          final bytes = utf8.encode(input);
                          final binary = bytes.map((b) => b.toRadixString(2).padLeft(8, '0')).join();
                          final hiddenStr = binary.replaceAll('0', '\u200C').replaceAll('1', '\u200D');

                          final langCode = Localizations.localeOf(context).languageCode;
                          final List<String> poems = _getLocalizedPoems(langCode);
                          final randomPoem = poems[Random().nextInt(poems.length)];
                          
                          final words = randomPoem.split(' ');
                          final chunkSize = (hiddenStr.length / words.length).ceil();
                          final buffer = StringBuffer();

                          for (int i = 0; i < words.length; i++) {
                            buffer.write(words[i]);
                            final start = i * chunkSize;
                            if (start < hiddenStr.length) {
                              final end = (start + chunkSize < hiddenStr.length) ? start + chunkSize : hiddenStr.length;
                              buffer.write(hiddenStr.substring(start, end));
                            }
                            if (i < words.length - 1) {
                              buffer.write(' ');
                            }
                          }

                          final finalPoem = buffer.toString();

                          setState(() {
                            _steganoResult = finalPoem;
                            _steganoController.text = finalPoem;
                          });
                        } catch (e) {
                          setState(() {
                            _steganoResult = "Erreur de génération.";
                          });
                        }
                      },
                      style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF222228)),
                      child: Text(AppTranslations.get(context, 'stegano_btn'), style: const TextStyle(fontSize: 10)),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: ElevatedButton(
                      onPressed: () {
                        try {
                          String textToScan = _steganoController.text;
                          if (!RegExp(r'[\u200C\u200D]').hasMatch(textToScan) && RegExp(r'[\u200C\u200D]').hasMatch(_steganoResult)) {
                            textToScan = _steganoResult;
                          }

                          final zwMatches = RegExp(r'[\u200C\u200D]').allMatches(textToScan).map((m) => m.group(0) == '\u200C' ? '0' : '1').join();

                          if (zwMatches.isNotEmpty && zwMatches.length >= 8) {
                            final validBitsLength = zwMatches.length - (zwMatches.length % 8);
                            final List<int> extractedBytes = [];
                            for (var i = 0; i < validBitsLength; i += 8) {
                              extractedBytes.add(int.parse(zwMatches.substring(i, i + 8), radix: 2));
                            }
                            final extractedKey = utf8.decode(extractedBytes, allowMalformed: true).trim();

                            if (extractedKey.isNotEmpty) {
                              setState(() {
                                _steganoResult = "PK: $extractedKey";
                                _peerAddressController.text = extractedKey;
                                _steganoController.clear();
                              });
                              _connectPeer();
                              return;
                            }
                          }
                          setState(() {
                            _steganoResult = "Aucune clé masquée détectée.";
                          });
                        } catch (e) {
                          setState(() {
                            _steganoResult = "Erreur de lecture du texte.";
                          });
                        }
                      },
                      style: ElevatedButton.styleFrom(backgroundColor: brandYellow, foregroundColor: Colors.black),
                      child: Text(AppTranslations.get(context, 'stegano_extract_btn'), style: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold)),
                    ),
                  ),
                ],
              ),
              if (_steganoResult.isNotEmpty) ...[
                const SizedBox(height: 8),
                SelectableText(_steganoResult, style: const TextStyle(color: brandYellow, fontSize: 11)),
              ],
              const SizedBox(height: 20),
              Text(AppTranslations.get(context, 'security_panel'), style: const TextStyle(color: Colors.redAccent, fontSize: 12, fontWeight: FontWeight.bold)),
              const SizedBox(height: 8),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  border: Border.all(color: Colors.redAccent.withValues(alpha: 0.5)),
                  borderRadius: BorderRadius.circular(8),
                  color: Colors.redAccent.withValues(alpha: 0.05),
                ),
                child: Column(
                  children: [
                    ElevatedButton.icon(
                      onPressed: _showChangePinDialog,
                      icon: const Icon(Icons.key, size: 16),
                      label: Text(AppTranslations.get(context, 'change_pin_btn')),
                      style: ElevatedButton.styleFrom(minimumSize: const Size(double.infinity, 42)),
                    ),
                    const SizedBox(height: 8),
                    ElevatedButton.icon(
                      onPressed: _triggerPanicPurge,
                      icon: const Icon(Icons.delete_forever, size: 16),
                      label: Text(AppTranslations.get(context, 'kill_switch_btn')),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: Colors.red,
                        foregroundColor: Colors.white,
                        minimumSize: const Size(double.infinity, 42),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 30),
            ],
          ),
        ),
      ),
    );
  }
}

class QRScannerScreen extends StatefulWidget {
  const QRScannerScreen({super.key});

  @override
  State<QRScannerScreen> createState() => _QRScannerScreenState();
}

class _QRScannerScreenState extends State<QRScannerScreen> {
  bool _isScanned = false;

  @override
  Widget build(BuildContext context) {
    const Color brandYellow = Color(0xFFFCBE0B);

    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: const Color(0xFF141416),
        iconTheme: const IconThemeData(color: brandYellow),
        title: const Text(
          'SCAN OPSEC',
          style: TextStyle(color: brandYellow, fontSize: 16, fontWeight: FontWeight.bold),
        ),
      ),
      body: Stack(
        children: [
          MobileScanner(
            onDetect: (capture) {
              if (_isScanned) return;

              final List<Barcode> barcodes = capture.barcodes;
              for (final barcode in barcodes) {
                if (barcode.rawValue != null) {
                  _isScanned = true;
                  Navigator.pop(context, barcode.rawValue);
                  return;
                }
              }
            },
          ),
          Center(
            child: Container(
              width: 250,
              height: 250,
              decoration: BoxDecoration(
                border: Border.all(color: brandYellow.withValues(alpha: 0.5), width: 2),
                borderRadius: BorderRadius.circular(12),
              ),
            ),
          ),
        ],
      ),
    );
  }
}