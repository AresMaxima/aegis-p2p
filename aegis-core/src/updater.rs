//! aegis-core/src/updater.rs
//!
//! P0-A.8a  (2026-10-18) — Vérification cryptographique des mises à jour.
//! P0-A.8d.1 (2026-10-19) — Schéma 10 champs + séparation de domaine.
//! C82      (2026-10-22) — Multi-source manifest fetch (Approche A).
//!
//! P-6 (Updater in-app) : empêche l'installation d'un APK altéré (MITM,
//! freeze, replay, downgrade, rollback forcé, compromission serveur,
//! XSS/social eng. via changelog).
//!
//! Séparation de domaine : la même clé ed25519 signe les LICENCES
//! (aegis_verify_license_key dans lib.rs) et les MANIFESTES (ici).
//! Pour empêcher structurellement tout cross-usage, chaque payload
//! signé est préfixé d'un domaine :
//!   - Licence : b"LICENSE:v1:"  || order_num.upper()
//!   - Manifeste : b"MANIFEST:v1:" || manifest_bytes_bruts

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Préfixe de domaine pour les manifestes (anti cross-usage avec licenses).
pub const MANIFEST_DOMAIN: &[u8] = b"MANIFEST:v1:";

/// Préfixe de domaine pour les licences (anti cross-usage avec manifestes).
pub const LICENSE_DOMAIN: &[u8] = b"LICENSE:v1:";

/// Âge maximal d'un manifeste (anti-freeze, anti-replay).
pub const MAX_MANIFEST_AGE_SECS: u64 = 90 * 24 * 3600;

/// Longueur maximale du changelog affiché (anti-DoS UI).
pub const MAX_CHANGELOG_LEN: usize = 500;

// =========================================================================
// Structures
// =========================================================================

/// Structure étendue du manifeste JSON signé (schéma v1.0, 10 champs).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateManifest {
    pub app_id: String,
    pub version: String,
    pub issued_at: String,
    pub min_from_version: String,
    pub apk_url: String,
    pub apk_host_whitelist: Vec<String>,
    pub apk_sha256: String,
    #[serde(default)]
    pub apk_signing_cert_sha256: Option<String>,
    pub force_update: bool,
    #[serde(default)]
    pub changelog: String,
}

// =========================================================================
// Erreurs
// =========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateError {
    InvalidSignature,
    HashMismatch,
    ParseError,
    WrongAppId,
    InvalidVersion,
    StaleManifest,
    FutureManifest,
    InvalidUrl,
    HostNotWhitelisted,
    InvalidSha256,
    InvalidChangelog,
    VersionTooOld,
}

impl UpdateError {
    pub fn to_code(self) -> i32 {
        match self {
            UpdateError::InvalidSignature => -60,
            UpdateError::HashMismatch => -61,
            UpdateError::ParseError => -62,
            UpdateError::WrongAppId => -70,
            UpdateError::InvalidVersion => -71,
            UpdateError::StaleManifest => -72,
            UpdateError::FutureManifest => -73,
            UpdateError::InvalidUrl => -74,
            UpdateError::HostNotWhitelisted => -75,
            UpdateError::InvalidSha256 => -76,
            UpdateError::InvalidChangelog => -77,
            UpdateError::VersionTooOld => -78,
        }
    }
}

// =========================================================================
// Vérification du manifeste
// =========================================================================

pub fn verify_manifest(
    manifest_bytes: &[u8],
    signature_bytes: &[u8; 64],
    admin_pubkey: &[u8; 32],
) -> Result<UpdateManifest, UpdateError> {
    let now_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    verify_manifest_at(manifest_bytes, signature_bytes, admin_pubkey, now_unix_secs)
}

pub fn verify_manifest_at(
    manifest_bytes: &[u8],
    signature_bytes: &[u8; 64],
    admin_pubkey: &[u8; 32],
    now_unix_secs: u64,
) -> Result<UpdateManifest, UpdateError> {
    let pubkey = VerifyingKey::from_bytes(admin_pubkey)
        .map_err(|_| UpdateError::InvalidSignature)?;
    let signature = Signature::from_bytes(signature_bytes);

    let mut signed_payload = Vec::with_capacity(MANIFEST_DOMAIN.len() + manifest_bytes.len());
    signed_payload.extend_from_slice(MANIFEST_DOMAIN);
    signed_payload.extend_from_slice(manifest_bytes);

    if pubkey.verify(&signed_payload, &signature).is_err() {
        return Err(UpdateError::InvalidSignature);
    }

    let manifest: UpdateManifest =
        serde_json::from_slice(manifest_bytes).map_err(|_| UpdateError::ParseError)?;

    validate_structure(&manifest, now_unix_secs)?;

    Ok(manifest)
}

fn validate_structure(m: &UpdateManifest, now_unix_secs: u64) -> Result<(), UpdateError> {
    if m.app_id != "aegis" {
        return Err(UpdateError::WrongAppId);
    }

    let version = parse_semver(&m.version).ok_or(UpdateError::InvalidVersion)?;
    let min_from = parse_semver(&m.min_from_version).ok_or(UpdateError::InvalidVersion)?;

    if compare_semver(&min_from, &version).is_gt() {
        return Err(UpdateError::InvalidVersion);
    }

    let issued_ts = parse_rfc3339_to_unix(&m.issued_at).ok_or(UpdateError::InvalidVersion)?;
    if issued_ts > now_unix_secs {
        return Err(UpdateError::FutureManifest);
    }
    if now_unix_secs.saturating_sub(issued_ts) > MAX_MANIFEST_AGE_SECS {
        return Err(UpdateError::StaleManifest);
    }

    if !m.apk_url.starts_with("https://") {
        return Err(UpdateError::InvalidUrl);
    }
    let host = extract_url_host(&m.apk_url).ok_or(UpdateError::InvalidUrl)?;
    if m.apk_host_whitelist.is_empty() {
        return Err(UpdateError::HostNotWhitelisted);
    }
    if !m.apk_host_whitelist.iter().any(|h| h.eq_ignore_ascii_case(&host)) {
        return Err(UpdateError::HostNotWhitelisted);
    }

    if !is_hex_64(&m.apk_sha256) {
        return Err(UpdateError::InvalidSha256);
    }

    if let Some(ref cert) = m.apk_signing_cert_sha256 {
        if !is_hex_64(cert) {
            return Err(UpdateError::InvalidSha256);
        }
    }

    if m.changelog.len() > MAX_CHANGELOG_LEN
        || m.changelog.contains('<')
        || m.changelog.contains('>')
    {
        return Err(UpdateError::InvalidChangelog);
    }

    Ok(())
}

pub fn check_updatable(m: &UpdateManifest, current_version: &str) -> Result<(), UpdateError> {
    let current = parse_semver(current_version).ok_or(UpdateError::InvalidVersion)?;
    let min_from = parse_semver(&m.min_from_version).ok_or(UpdateError::InvalidVersion)?;

    if compare_semver(&current, &min_from).is_lt() {
        return Err(UpdateError::VersionTooOld);
    }
    Ok(())
}

// =========================================================================
// Vérification du hash APK
// =========================================================================

pub fn verify_apk_hash(apk_bytes: &[u8], expected_hash_hex: &str) -> Result<(), UpdateError> {
    let mut hasher = Sha256::new();
    hasher.update(apk_bytes);
    let computed_hash = hex::encode(hasher.finalize());

    if computed_hash != expected_hash_hex {
        return Err(UpdateError::HashMismatch);
    }

    Ok(())
}

// =========================================================================
// Helpers
// =========================================================================

fn parse_semver(s: &str) -> Option<[u32; 3]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    Some([
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ])
}

fn compare_semver(a: &[u32; 3], b: &[u32; 3]) -> std::cmp::Ordering {
    a.cmp(b)
}

fn parse_rfc3339_to_unix(s: &str) -> Option<u64> {
    let bytes = s.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return None;
    }
    let year: i64 = s[0..4].parse().ok()?;
    let month: u32 = s[5..7].parse().ok()?;
    let day: u32 = s[8..10].parse().ok()?;
    let hour: u32 = s[11..13].parse().ok()?;
    let min: u32 = s[14..16].parse().ok()?;
    let sec: u32 = s[17..19].parse().ok()?;

    if !(1970..=9999).contains(&year) { return None; }
    if !(1..=12).contains(&month) { return None; }
    if !(1..=31).contains(&day) { return None; }
    if hour > 23 || min > 59 || sec > 60 { return None; }

    let days = days_from_civil(year, month, day);
    if days < 0 { return None; }
    Some(days as u64 * 86400 + (hour as u64 * 3600) + (min as u64 * 60) + sec as u64)
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let m = month as i32;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + day as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u32;
    era * 146097 + doe as i64 - 719468
}

fn extract_url_host(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let host_end = rest
        .find(|c: char| c == '/' || c == ':' || c == '?')
        .unwrap_or(rest.len());
    let host = &rest[..host_end];
    if host.is_empty() || host.contains('@') {
        return None;
    }
    Some(host.to_string())
}

fn is_hex_64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// =========================================================================
// C82 — Multi-source manifest fetch (Approche A)
// =========================================================================
//
// Types et helpers pour la récupération multi-source du manifest.
// Les sources sont essayées dans l'ordre (LocalCache → GitHub → Onion →
// IPFS → Primary). Premier manifest valide (signature ed25519 vérifiée)
// gagne.
//
// Si toutes les sources échouent → UpdateCheckResult::failure. Pas de
// blocage : l'utilisateur continue à utiliser AEGIS.

/// TTL du cache local : 7 jours.
pub const LOCAL_CACHE_TTL_SECS: u64 = 7 * 24 * 3600;

/// Liste des sources de manifest, dans l'ordre de préférence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestSource {
    LocalCache,
    GitHubReleases,
    OnionService,
    IpfsGateway,
    PrimaryServer,
}

impl ManifestSource {
    /// Label pour les logs (non-sensible).
    pub fn label(self) -> &'static str {
        match self {
            ManifestSource::LocalCache => "local_cache",
            ManifestSource::GitHubReleases => "github",
            ManifestSource::OnionService => "onion",
            ManifestSource::IpfsGateway => "ipfs",
            ManifestSource::PrimaryServer => "primary",
        }
    }

    /// Toutes les sources, dans l'ordre de préférence.
    pub fn all() -> [ManifestSource; 5] {
        [
            ManifestSource::LocalCache,
            ManifestSource::GitHubReleases,
            ManifestSource::OnionService,
            ManifestSource::IpfsGateway,
            ManifestSource::PrimaryServer,
        ]
    }
}

/// Résultat d'une tentative de fetch sur une source.
#[derive(Debug)]
pub enum SourceFetchResult {
    /// Manifest + signature récupérés (signature PAS encore vérifiée).
    Fetched {
        manifest_bytes: Vec<u8>,
        sig_bytes: Vec<u8>,
        source: ManifestSource,
    },
    /// Source indisponible (timeout, 404, DNS, etc.).
    Unavailable {
        source: ManifestSource,
        reason: String,
    },
    /// Manifest récupéré mais signature invalide.
    InvalidSignature {
        source: ManifestSource,
        rc: i32,
    },
}

/// Timestamp Unix actuel (secondes).
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Vrai si le cache local est encore frais (TTL 7j).
pub fn local_cache_is_fresh(cached_at_unix: u64, now_unix: u64) -> bool {
    now_unix.saturating_sub(cached_at_unix) < LOCAL_CACHE_TTL_SECS
}

/// Vérifie qu'un manifest récupéré (bytes bruts + signature) est valide
/// et correspond à une version strictement supérieure à `current_version`.
///
/// # Arguments
/// - `manifest_bytes` : contenu JSON brut du manifest
/// - `sig_bytes`      : signature ed25519 (doit faire exactement 64 octets)
/// - `current_version` : version actuelle du client (ex: "3.1.0")
/// - `now_unix_secs`   : timestamp de référence (injectable pour les tests)
///
/// # Retour
/// - `Ok(Some(manifest))` : manifest valide + version > current
/// - `Ok(None)`           : manifest valide + version ≤ current (à jour)
/// - `Err(UpdateError)`   : signature invalide, manifest malformé, etc.
pub fn check_fetched_manifest(
    manifest_bytes: &[u8],
    sig_bytes: &[u8],
    current_version: &str,
    now_unix_secs: u64,
) -> Result<Option<UpdateManifest>, UpdateError> {
    // 1. Vérifier la longueur de la signature (64 octets exactement)
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| UpdateError::InvalidSignature)?;

    // 2. Vérifier la signature ed25519 + parser (via verify_manifest_at)
    let manifest = verify_manifest_at(
        manifest_bytes,
        &sig_arr,
        &crate::ADMIN_PUBLIC_KEY_BYTES,
        now_unix_secs,
    )?;

    // 3. Vérifier qu'on peut updater (min_from_version ≤ current)
    check_updatable(&manifest, current_version)?;

    // 4. Retourner Some(manifest) si version > current, sinon None
    let current = parse_semver(current_version).ok_or(UpdateError::InvalidVersion)?;
    let new_version = parse_semver(&manifest.version).ok_or(UpdateError::InvalidVersion)?;

    if compare_semver(&new_version, &current).is_gt() {
        Ok(Some(manifest))
    } else {
        Ok(None)
    }
}

// =========================================================================
// Tests
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn valid_manifest_json() -> Vec<u8> {
        let json = r#"{
            "app_id":"aegis",
            "version":"3.2.0",
            "issued_at":"2026-10-19T12:00:00Z",
            "min_from_version":"3.0.0",
            "apk_url":"https://aresmaxima.com/update/aegis-3.2.0.apk",
            "apk_host_whitelist":["aresmaxima.com"],
            "apk_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "apk_signing_cert_sha256":null,
            "force_update":false,
            "changelog":"Correctifs de securite."
        }"#;
        json.as_bytes().to_vec()
    }

    const NOW_TEST: u64 = 1_792_411_200;

    fn sign_manifest(signing_key: &SigningKey, bytes: &[u8]) -> [u8; 64] {
        let mut payload = Vec::with_capacity(MANIFEST_DOMAIN.len() + bytes.len());
        payload.extend_from_slice(MANIFEST_DOMAIN);
        payload.extend_from_slice(bytes);
        signing_key.sign(&payload).to_bytes()
    }

    fn generate_test_keypair() -> (SigningKey, [u8; 32]) {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    #[test]
    fn test_verify_manifest_valid_v10() {
        let (sk, pk) = generate_test_keypair();
        let bytes = valid_manifest_json();
        let sig = sign_manifest(&sk, &bytes);

        let r = verify_manifest_at(&bytes, &sig, &pk, NOW_TEST);
        assert!(r.is_ok(), "manifest valide rejeté : {:?}", r.err());
        let m = r.unwrap();
        assert_eq!(m.app_id, "aegis");
        assert_eq!(m.version, "3.2.0");
        assert!(!m.force_update);
    }

    #[test]
    fn test_verify_manifest_rejects_old_domain_less_signature() {
        let (sk, pk) = generate_test_keypair();
        let bytes = valid_manifest_json();
        let old_sig = sk.sign(&bytes).to_bytes();

        let r = verify_manifest_at(&bytes, &old_sig, &pk, NOW_TEST);
        assert_eq!(r, Err(UpdateError::InvalidSignature));
    }

    #[test]
    fn test_verify_manifest_rejects_wrong_app_id() {
        let (sk, pk) = generate_test_keypair();
        let mut json: serde_json::Value = serde_json::from_slice(&valid_manifest_json()).unwrap();
        json["app_id"] = serde_json::Value::String("otherapp".to_string());
        let bytes = serde_json::to_vec(&json).unwrap();
        let sig = sign_manifest(&sk, &bytes);

        let r = verify_manifest_at(&bytes, &sig, &pk, NOW_TEST);
        assert_eq!(r, Err(UpdateError::WrongAppId));
    }

    #[test]
    fn test_verify_manifest_rejects_stale() {
        let (sk, pk) = generate_test_keypair();
        let mut json: serde_json::Value = serde_json::from_slice(&valid_manifest_json()).unwrap();
        json["issued_at"] = serde_json::Value::String("2025-01-01T00:00:00Z".to_string());
        let bytes = serde_json::to_vec(&json).unwrap();
        let sig = sign_manifest(&sk, &bytes);

        let r = verify_manifest_at(&bytes, &sig, &pk, NOW_TEST);
        assert_eq!(r, Err(UpdateError::StaleManifest));
    }

    #[test]
    fn test_verify_manifest_rejects_future_timestamp() {
        let (sk, pk) = generate_test_keypair();
        let mut json: serde_json::Value = serde_json::from_slice(&valid_manifest_json()).unwrap();
        json["issued_at"] = serde_json::Value::String("2030-01-01T00:00:00Z".to_string());
        let bytes = serde_json::to_vec(&json).unwrap();
        let sig = sign_manifest(&sk, &bytes);

        let r = verify_manifest_at(&bytes, &sig, &pk, NOW_TEST);
        assert_eq!(r, Err(UpdateError::FutureManifest));
    }

    #[test]
    fn test_verify_manifest_rejects_host_not_whitelisted() {
        let (sk, pk) = generate_test_keypair();
        let mut json: serde_json::Value = serde_json::from_slice(&valid_manifest_json()).unwrap();
        json["apk_url"] = serde_json::Value::String("https://evil.com/aegis.apk".to_string());
        let bytes = serde_json::to_vec(&json).unwrap();
        let sig = sign_manifest(&sk, &bytes);

        let r = verify_manifest_at(&bytes, &sig, &pk, NOW_TEST);
        assert_eq!(r, Err(UpdateError::HostNotWhitelisted));
    }

    #[test]
    fn test_verify_manifest_rejects_http_url() {
        let (sk, pk) = generate_test_keypair();
        let mut json: serde_json::Value = serde_json::from_slice(&valid_manifest_json()).unwrap();
        json["apk_url"] = serde_json::Value::String("http://aresmaxima.com/aegis.apk".to_string());
        let bytes = serde_json::to_vec(&json).unwrap();
        let sig = sign_manifest(&sk, &bytes);

        let r = verify_manifest_at(&bytes, &sig, &pk, NOW_TEST);
        assert_eq!(r, Err(UpdateError::InvalidUrl));
    }

    #[test]
    fn test_verify_manifest_rejects_changelog_with_html() {
        let (sk, pk) = generate_test_keypair();
        let mut json: serde_json::Value = serde_json::from_slice(&valid_manifest_json()).unwrap();
        json["changelog"] = serde_json::Value::String("<script>alert(1)</script>".to_string());
        let bytes = serde_json::to_vec(&json).unwrap();
        let sig = sign_manifest(&sk, &bytes);

        let r = verify_manifest_at(&bytes, &sig, &pk, NOW_TEST);
        assert_eq!(r, Err(UpdateError::InvalidChangelog));
    }

    #[test]
    fn test_verify_manifest_rejects_bad_sha256() {
        let (sk, pk) = generate_test_keypair();
        let mut json: serde_json::Value = serde_json::from_slice(&valid_manifest_json()).unwrap();
        json["apk_sha256"] = serde_json::Value::String(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        );
        let bytes = serde_json::to_vec(&json).unwrap();
        let sig = sign_manifest(&sk, &bytes);

        let r = verify_manifest_at(&bytes, &sig, &pk, NOW_TEST);
        assert_eq!(r, Err(UpdateError::InvalidSha256));
    }

    #[test]
    fn test_check_updatable_rejects_too_old_client() {
        let json: serde_json::Value = serde_json::from_slice(&valid_manifest_json()).unwrap();
        let manifest: UpdateManifest = serde_json::from_value(json).unwrap();
        let r = check_updatable(&manifest, "2.9.0");
        assert_eq!(r, Err(UpdateError::VersionTooOld));
        assert!(check_updatable(&manifest, "3.0.0").is_ok());
    }

    #[test]
    fn test_verify_apk_hash_valid() {
        let apk_bytes = b"dummy_apk_content";
        let mut hasher = Sha256::new();
        hasher.update(apk_bytes);
        let expected_hash = hex::encode(hasher.finalize());

        assert!(verify_apk_hash(apk_bytes, &expected_hash).is_ok());
    }

    #[test]
    fn test_verify_apk_hash_mismatch() {
        let apk_bytes = b"dummy_apk_content";
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";

        assert_eq!(
            verify_apk_hash(apk_bytes, wrong_hash),
            Err(UpdateError::HashMismatch)
        );
    }
}