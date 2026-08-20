use rand::Rng;

// Caractères Unicode Invisibles (Zero-Width Steganography)
const ZW_ZERO: char = '\u{200B}'; // Zero-Width Space (représente le bit 0)
const ZW_ONE: char  = '\u{200C}'; // Zero-Width Non-Joiner (représente le bit 1)
const ZW_MARK: char = '\u{200D}'; // Zero-Width Joiner (Marqueur de début/fin)

/// Banque de poèmes hôtes pour éviter la redondance
const COVER_POEMS: &[&str] = &[
    "Le temps s'écoule en silence le long des heures grises. La nuit recouvre doucement les ombres du passé. Un souffle frais traverse la fenêtre ouverte.",
    "Au loin, les étoiles brillent au-dessus des collines. Les feuilles tombent sans un bruit dans la forêt endormie. La rivière poursuit sa course vers la mer.",
    "Sous la pluie fine de novembre, la ville s'endort paisiblement. Rien ne trouble la quiétude de cet instant suspendu. Le vent murmure d'anciens secrets.",
    "Des lueurs dorées traversent le brouillard matinal. L'horizon s'éclaire doucement sous un ciel d'argent. Tout redevient calme après la tempête.",
    "L'ombre du vieux chêne s'étend sur le sol gelé. Dans le silence absolu de la nuit, le froid s'installe. Seule la lune observe la terre endormie."
];

/// Retourne un poème au hasard dans la banque hôte
pub fn get_random_cover_poem() -> &'static str {
    let mut rng = rand::thread_rng();
    let index = rng.gen_range(0..COVER_POEMS.len());
    COVER_POEMS[index]
}

/// Noyage/Dissimulation d'une phrase mnémonique ou clé dans un texte hôte.
/// Si `cover_text` est vide ou None, un poème est choisi aléatoirement.
pub fn hide_mnemonic_in_text(mnemonic: &str, cover_text_opt: Option<&str>) -> Result<String, String> {
    if mnemonic.trim().is_empty() {
        return Err("La phrase mnémonique est vide".to_string());
    }

    // Choix du poème : celui fourni par l'utilisateur ou un poème aléatoire
    let cover_text = match cover_text_opt {
        Some(text) if !text.trim().is_empty() => text,
        _ => get_random_cover_poem(),
    };

    // 1. Convertit la phrase mnémonique en binaire (suite de '0' et '1')
    let mut binary_payload = String::new();
    for byte in mnemonic.as_bytes() {
        binary_payload.push_str(&format!("{:08b}", byte));
    }

    // 2. Transforme le binaire en caractères invisibles
    let mut invisible_payload = String::new();
    invisible_payload.push(ZW_MARK); // Marqueur de début
    for bit in binary_payload.chars() {
        if bit == '0' {
            invisible_payload.push(ZW_ZERO);
        } else if bit == '1' {
            invisible_payload.push(ZW_ONE);
        }
    }
    invisible_payload.push(ZW_MARK); // Marqueur de fin

    // 3. Infiltre la charge invisible juste après le premier espace du poème
    let mut result = String::new();
    if let Some(pos) = cover_text.find(' ') {
        let (first_word, rest) = cover_text.split_at(pos);
        result.push_str(first_word);
        result.push_str(&invisible_payload); // On cache la clé ici
        result.push_str(rest);
    } else {
        result.push_str(cover_text);
        result.push_str(&invisible_payload);
    }

    Ok(result)
}

/// Extraction de la phrase mnémonique ou clé à partir du texte hôte.
pub fn extract_mnemonic_from_text(stego_text: &str) -> Result<String, String> {
    // 1. Cherche les marqueurs de début et de fin (ZW_MARK)
    // CORRECTION SYNTAXE : Remplacement de ok_ok_or_else par ok_or_else
    let start_idx = stego_text.find(ZW_MARK)
        .ok_or_else(|| "Aucun message stéganographié détecté dans le texte".to_string())?;
    
    let after_start = &stego_text[start_idx + ZW_MARK.len_utf8()..];
    
    let end_idx = after_start.find(ZW_MARK)
        .ok_or_else(|| "Marqueur de fin stéganographique manquant".to_string())?;

    let invisible_payload = &after_start[..end_idx];

    // 2. Reconstitution du binaire à partir des caractères invisibles
    let mut binary_str = String::new();
    for c in invisible_payload.chars() {
        if c == ZW_ZERO {
            binary_str.push('0');
        } else if c == ZW_ONE {
            binary_str.push('1');
        }
    }

    if binary_str.is_empty() || binary_str.len() % 8 != 0 {
        return Err("Charge utile stéganographique corrompue".to_string());
    }

    // 3. Conversion du binaire vers le texte original (UTF-8)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_steganography_hide_and_extract() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        // Test 1: Avec un poème aléatoire automatique
        let stego = hide_mnemonic_in_text(mnemonic, None).unwrap();
        
        // Vérifie qu'AUCUN crochet ou mot mnémonique n'est visible en clair
        assert!(!stego.contains("[abandon]"));
        assert!(!stego.contains("abandon"));

        // Test d'extraction
        let extracted = extract_mnemonic_from_text(&stego).unwrap();
        assert_eq!(extracted, mnemonic);
    }
}