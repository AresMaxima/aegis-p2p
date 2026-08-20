import 'dart:async';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

class CryptoService {
  final Pbkdf2 _pbkdf2 = Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: 100000,
    bits: 256,
  );

  Future<SecretKey> deriveKey(String pin, List<int> salt) async {
    return await _pbkdf2.deriveKeyFromPassword(
      password: pin,
      nonce: salt,
    );
  }

  Future<String?> decryptData(
    List<int> cipherText,
    List<int> nonce,
    List<int> macTag,
    SecretKey key,
  ) async {
    try {
      final algorithm = AesGcm.with256bits();
      final secretBox = SecretBox(
        cipherText,
        nonce: nonce,
        mac: Mac(macTag),
      );
      final decryptedBytes = await algorithm.decrypt(
        secretBox,
        secretKey: key,
      );
      return String.fromCharCodes(decryptedBytes);
    } catch (e) {
      return null;
    }
  }
}