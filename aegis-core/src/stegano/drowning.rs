//! aegis-core/src/stegano/drowning.rs
//! Dissimulation Stéganographique Textuelle Zero-Width & Infiltration de Clés.
//!
//! Q2 FIX v2.3 (2026-09-24) — Distribution uniforme du payload.
//!
//! Historique :
//!   v2.0 : U+200B → U+2060 (break opportunity éliminé)
//!   v2.1 : ZWNJ/ZWJ → U+FEFF/U+034F (shaping modifiers éliminés)
//!   v2.2 : Dart — retrait italic + height:1.5 (rendu amélioré)
//!   → L'écartement anormal persistait.
//!
//! v2.3 — CAUSE RÉELLE : un bloc massif de 800+ caractères Cf collés après
//! le premier espace sature le shaping engine (Skia/HarfBuzz). Le text run
//! est découpé en segments aux frontières de classe → micro-avances
//! cumulatives → "espacement entre les mots".
//!
//! SOLUTION : distribution. Après chaque caractère visible du poème, on
//! insère un petit nombre de bits (payload_len / poem_len ≈ 4). Jamais
//! plus de ~5 Cf consécutifs → shaping normal.
//!
//! L'extraction reste inchangée : elle lit tous les ZW_ZERO/ZW_ONE entre
//! les 2 marqueurs, ignorant les caractères visibles intercalés.

use rand::Rng;

// Caractères Unicode Invisibles (Zero-Width Steganography)
const ZW_ZERO: char = '\u{2060}'; // Word Joiner             — bit 0
const ZW_ONE:  char = '\u{FEFF}'; // Zero Width No-Break Space — bit 1
const ZW_MARK: char = '\u{034F}'; // Combining Grapheme Joiner — marqueur début/fin

/// Banque de poèmes hôtes pour éviter la redondance
const COVER_POEMS: &[&str] = &[
    "Le temps s'écoule en silence le long des heures grises. La nuit recouvre doucement les ombres du passé. Un souffle frais traverse la fenêtre ouverte.",
    "Au loin, les étoiles brillent au-dessus des collines. Les feuilles tombent sans un bruit dans la forêt endormie. La rivière poursuit sa course vers la mer.",
    "Sous la pluie fine de novembre, la ville s'endort paisiblement. Rien ne trouble la quiétude de cet instant suspendu. Le vent murmure d'anciens secrets.",
    "Des lueurs dorées traversent le brouillard matinal. L'horizon s'éclaire doucement sous un ciel d'argent. Tout redevient calme après la tempête.",
    "L'ombre du vieux chêne s'étend sur le sol gelé. Dans le silence absolu de la nuit, le froid s'installe. Seule la lune observe la terre endormie.",
];

/// Retourne un poème au hasard dans la banque hôte
pub fn get_random_cover_poem() -> &'static str {
    let mut rng = rand::thread_rng();
    let index = rng.gen_range(0..COVER_POEMS.len());
    COVER_POEMS[index]
}

/// Noyage/Dissimulation d'une phrase mnémonique ou clé dans un texte hôte.
///
/// v2.3 : distribution uniforme des bits sur tout le poème.
pub fn hide_mnemonic_in_text(
    mnemonic: &str,
    cover_text_opt: Option<&str>,
) -> Result<String, String> {
    if mnemonic.trim().is_empty() {
        return Err("La phrase mnémonique est vide".to_string());
    }

    let cover_text = match cover_text_opt {
        Some(text) if !text.trim().is_empty() => text,
        _ => get_random_cover_poem(),
    };

    // 1. Convertit la phrase mnémonique en binaire
    let mut binary_payload = String::new();
    for byte in mnemonic.as_bytes() {
        binary_payload.push_str(&format!("{:08b}", byte));
    }

    let payload_bits: Vec<char> = binary_payload.chars().collect();
    if payload_bits.is_empty() {
        return Ok(cover_text.to_string());
    }

    // 2. Prépare le poème pour distribution
    let cover_chars: Vec<char> = cover_text.chars().collect();
    let cover_len = cover_chars.len();
    if cover_len == 0 {
        return Err("Poème hôte vide".to_string());
    }

    // 3. Construit la sortie avec distribution
    let mut result = String::with_capacity(cover_text.len() + payload_bits.len() + 2);
    result.push(ZW_MARK); // marqueur début

    let mut bits_inserted: usize = 0;
    for (i, ch) in cover_chars.iter().enumerate() {
        // Émet le caractère visible
        result.push(*ch);

        // Combien de bits doivent avoir été insérés après ce caractère ?
        // target(i) = floor((i+1) * payload_len / cover_len)
        let target = ((i + 1) * payload_bits.len()) / cover_len;

        // Insère les bits nécessaires (petit bloc ~1 à ~10 chars)
        while bits_inserted < target && bits_inserted < payload_bits.len() {
            result.push(if payload_bits[bits_inserted] == '0' {
                ZW_ZERO
            } else {
                ZW_ONE
            });
            bits_inserted += 1;
        }
    }

    // Reste éventuel (arrondi de la division entière)
    while bits_inserted < payload_bits.len() {
        result.push(if payload_bits[bits_inserted] == '0' {
            ZW_ZERO
        } else {
            ZW_ONE
        });
        bits_inserted += 1;
    }

    result.push(ZW_MARK); // marqueur fin

    Ok(result)
}

/// Extraction de la phrase mnémonique ou clé à partir du texte hôte.
///
/// v2.3 : lit TOUS les ZW_ZERO/ZW_ONE entre les 2 marqueurs, en ignorant
/// les caractères visibles intercalés (payload distribué).
pub fn extract_mnemonic_from_text(stego_text: &str) -> Result<String, String> {
    // 1. Cherche les marqueurs
    let start_idx = stego_text
        .find(ZW_MARK)
        .ok_or_else(|| "Aucun message stéganographié détecté dans le texte".to_string())?;

    let after_start = &stego_text[start_idx + ZW_MARK.len_utf8()..];

    let end_idx = after_start
        .find(ZW_MARK)
        .ok_or_else(|| "Marqueur de fin stéganographique manquant".to_string())?;

    let between_marks = &after_start[..end_idx];

    // 2. Extrait les bits (ignore les caractères visibles distribués)
    let mut binary_str = String::new();
    for c in between_marks.chars() {
        if c == ZW_ZERO {
            binary_str.push('0');
        } else if c == ZW_ONE {
            binary_str.push('1');
        }
        // les caractères visibles du poème sont ignorés
    }

    if binary_str.is_empty() || binary_str.len() % 8 != 0 {
        return Err("Charge utile stéganographique corrompue".to_string());
    }

    // 3. Conversion binaire → UTF-8
    let bytes: Vec<u8> = binary_str
        .as_bytes()
        .chunks(8)
        .filter_map(|chunk| {
            let chunk_str = std::str::from_utf8(chunk).ok()?;
            u8::from_str_radix(chunk_str, 2).ok()
        })
        .collect();

    String::from_utf8(bytes)
        .map_err(|_| "Échec du décodage de la phrase mnémonique en UTF-8".to_string())
}

// =========================================================================
// TESTS UNITAIRES
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_steganography_hide_and_extract() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let stego = hide_mnemonic_in_text(mnemonic, None).unwrap();
        assert!(!stego.contains("[abandon]"));
        assert!(!stego.contains("abandon"));
        let extracted = extract_mnemonic_from_text(&stego).unwrap();
        assert_eq!(extracted, mnemonic);
    }

    #[test]
    fn test_steganography_custom_cover_text() {
        let mnemonic = "secret_key_123";
        let custom_cover = "Ceci est un texte de couverture personnalisé pour le test.";
        let stego = hide_mnemonic_in_text(mnemonic, Some(custom_cover)).unwrap();
        let extracted = extract_mnemonic_from_text(&stego).unwrap();
        assert_eq!(extracted, mnemonic);
    }

    #[test]
    fn test_q2_no_zwsp_in_output() {
        let mnemonic = "test payload";
        let cover = "Un poème hôte quelconque pour la vérification.";
        let stego = hide_mnemonic_in_text(mnemonic, Some(cover)).unwrap();
        assert!(!stego.contains('\u{200B}'));
        assert!(stego.contains('\u{2060}'));
    }

    #[test]
    fn test_q2_no_shaping_modifiers_in_output() {
        let mnemonic = "test shaping neutral";
        let cover = "Poème hôte de test pour shaping.";
        let stego = hide_mnemonic_in_text(mnemonic, Some(cover)).unwrap();
        assert!(!stego.contains('\u{200C}'));
        assert!(!stego.contains('\u{200D}'));
    }

    #[test]
    fn test_q2_roundtrip_after_v2_3() {
        let mnemonic = "phrase mnémonique de test avec accents é à ç";
        let cover = "Poème hôte de test.";
        let stego = hide_mnemonic_in_text(mnemonic, Some(cover)).unwrap();
        let extracted = extract_mnemonic_from_text(&stego).unwrap();
        assert_eq!(extracted, mnemonic);
    }

    #[test]
    fn test_q2_all_chars_neutral() {
        assert_eq!(ZW_ZERO, '\u{2060}');
        assert_eq!(ZW_ONE,  '\u{FEFF}');
        assert_eq!(ZW_MARK, '\u{034F}');
    }

    // v2.3 : Preuve que la distribution évite les blocs massifs de Cf
    #[test]
    fn test_q2_v2_3_no_massive_cf_block() {
        let mnemonic = "test distribution effective contre les blocs";
        let cover = "Poème relativement court pour tester la distribution v2.3.";
        let stego = hide_mnemonic_in_text(mnemonic, Some(cover)).unwrap();

        // Compte les runs de caractères Cf consécutifs
        let mut max_run = 0usize;
        let mut current_run = 0usize;
        for c in stego.chars() {
            if c == ZW_ZERO || c == ZW_ONE {
                current_run += 1;
                if current_run > max_run { max_run = current_run; }
            } else {
                current_run = 0;
            }
        }

        // Avec distribution : max_run devrait être < 50.
        assert!(
            max_run < 50,
            "REGRESSION Q2 v2.3 : bloc massif de {max_run} chars Cf détecté. \
             La distribution ne fonctionne pas."
        );
    }
}