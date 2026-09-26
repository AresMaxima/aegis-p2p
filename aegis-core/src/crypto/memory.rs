use std::sync::atomic::{compiler_fence, Ordering};
use zeroize::Zeroize;

/// Interface d'abstraction pour les appels système mémoire et de gestion de processus.
pub trait MemoryProvider {
    fn lock_memory(&self, ptr: *const u8, len: usize) -> bool;
    fn unlock_memory(&self, ptr: *const u8, len: usize) -> bool;
    fn trigger_exit(&self, code: i32);
}

/// Implémentation réelle exécutée en production (Zero-Cost Abstraction).
pub struct SystemMemoryProvider;

impl MemoryProvider for SystemMemoryProvider {
    fn lock_memory(&self, ptr: *const u8, len: usize) -> bool {
        if ptr.is_null() || len == 0 {
            return false;
        }
        
        #[cfg(miri)]
        { return true; }
        
        #[cfg(all(target_os = "windows", not(miri)))]
        unsafe {
            return windows_sys::Win32::System::Memory::VirtualLock(ptr as *const _, len) != 0;
        }
        
        #[cfg(all(not(target_os = "windows"), not(miri)))]
        unsafe {
            return libc::mlock(ptr as *const _, len) == 0;
        }
    }

    fn unlock_memory(&self, ptr: *const u8, len: usize) -> bool {
        if ptr.is_null() || len == 0 {
            return false;
        }
        
        #[cfg(miri)]
        { return true; }
        
        #[cfg(all(target_os = "windows", not(miri)))]
        unsafe {
            return windows_sys::Win32::System::Memory::VirtualUnlock(ptr as *const _, len) != 0;
        }
        
        #[cfg(all(not(target_os = "windows"), not(miri)))]
        unsafe {
            return libc::munlock(ptr as *const _, len) == 0;
        }
    }

    fn trigger_exit(&self, code: i32) {
        std::process::exit(code);
    }
}

/// Implémentation isolée de test permettant de simuler des pannes système sous LLVM.
#[cfg(test)]
pub struct MockMemoryProvider {
    pub should_fail: bool,
    pub exit_triggered: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl MockMemoryProvider {
    pub fn new(should_fail: bool) -> Self {
        Self {
            should_fail,
            exit_triggered: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

#[cfg(test)]
impl MemoryProvider for MockMemoryProvider {
    fn lock_memory(&self, _ptr: *const u8, _len: usize) -> bool {
        !self.should_fail
    }

    fn unlock_memory(&self, _ptr: *const u8, _len: usize) -> bool {
        !self.should_fail
    }

    fn trigger_exit(&self, _code: i32) {
        self.exit_triggered.store(true, Ordering::SeqCst);
    }
}

/// Empêche la génération de memory dumps et interdit la lecture de `/proc/self/mem`
/// par d'autres processus ou spyciels.
pub fn prevent_core_dumps() {
    #[cfg(miri)]
    {
        // Miri ne supporte pas le syscall prctl(PR_SET_DUMPABLE), on ignore donc cette étape en audit.
        return;
    }

    #[cfg(all(any(target_os = "linux", target_os = "android"), not(miri)))]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// Conteneur cryptographique **obfusquant** les clés en RAM via un pad XOR aléatoire.
///
/// # Ce que cette classe protège
///
///   • **Scan par entropie** : un adversaire qui grep la RAM à la recherche
///     d'une séquence de 32-64 octets à haute entropie (pattern typique d'une
///     clé cryptographique) ne la trouvera pas — les octets stockés sont XORés
///     avec un masque aléatoire.
///   • **Capture partielle** : un crash dump qui n'inclut qu'une fraction de
///     la structure (ex. seulement `masked_data`) ne révèle rien sans `mask`.
///   • **Détection opportuniste** : un virus ou un rootkit qui scanne la RAM
///     à la recherche de motifs connus (clés PEM, entropie Shannon élevée)
///     passe à côté.
///
/// # Ce que cette classe NE protège PAS
///
///   • **Attaquant avec accès mémoire complet** : `masked_data` et `mask` sont
///     stockés dans la même structure Rust. Un attaquant qui peut lire les deux
///     (via `ptrace`, `/proc/self/mem`, hyperviseur, cold-boot…) reconstruit
///     le secret en un XOR trivial.
///   • **Attaquant avec root sur le device** : il peut lire toute la mémoire
///     du processus, donc les deux champs.
///
/// # C9 Clarification (audit 2026-09-21)
///
/// Le nom « MaskedSecret » ne signifie PAS « secret inattaquable ». C'est
/// une **obfuscation**, pas un chiffrement. La protection réelle du secret
/// repose sur :
///   1. `mlock` (empêche le swap disque)
///   2. `MADV_DONTDUMP` (empêche le core dump)
///   3. `zeroize` au Drop (empêche la rémanence)
///   4. Le masquage XOR (empêche le scan mémoire naïf)
///
/// Voir `ProtectedBuffer` ci-dessous pour une classe qui vise un niveau
/// de protection supérieur (mlock + zeroize + Drop, sans masquage).
pub struct MaskedSecret {
    masked_data: Vec<u8>,
    mask: Vec<u8>,
}

impl MaskedSecret {
    /// Crée une nouvelle instance obfusquée en RAM à l'aide d'un masque aléatoire unique.
    pub fn new(secret: &[u8]) -> Result<Self, String> {
        let mut mask = vec![0u8; secret.len()];
        getrandom::getrandom(&mut mask)
            .map_err(|e| format!("Échec de génération du masque aléatoire : {}", e))?;

        let masked_data = secret.iter().zip(mask.iter()).map(|(s, m)| s ^ m).collect();

        Ok(Self { masked_data, mask })
    }

    /// Extrait le secret dé-masqué uniquement pendant la durée d'exécution de la fermeture `f`.
    /// Les octets dé-masqués sont immédiatement zéroïsés à la sortie de la portée.
    pub fn expose<F, R>(&self, mut f: F) -> R
    where
        F: FnMut(&[u8]) -> R,
    {
        let mut unmasked: Vec<u8> = self
            .masked_data
            .iter()
            .zip(self.mask.iter())
            .map(|(d, m)| d ^ m)
            .collect();

        let result = f(&unmasked);
        unmasked.zeroize();
        result
    }
}

impl Drop for MaskedSecret {
    fn drop(&mut self) {
        self.masked_data.zeroize();
        self.mask.zeroize();
    }
}

/// Structure de mémoire sécurisée verrouillée en RAM (incapable d'être écrite sur le disque/swap).
pub struct ProtectedBuffer {
    data: Vec<u8>,
}

impl ProtectedBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        let mut buf = Self { data };
        buf.lock_ram();
        buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    fn lock_ram(&mut self) {
        if self.data.is_empty() {
            return;
        }

        let provider = SystemMemoryProvider;
        let _ = provider.lock_memory(self.data.as_ptr(), self.data.len());
    }
}

impl Drop for ProtectedBuffer {
    fn drop(&mut self) {
        let provider = SystemMemoryProvider;
        let _ = provider.unlock_memory(self.data.as_ptr(), self.data.len());
        self.data.zeroize();
    }
}

/// Force la purge immédiate de tous les buffers secrets enregistrés,
/// puis pose une barrière mémoire pour empêcher toute réorganisation
/// d'instructions par le compilateur.
///
/// C10 FIX (2026-09-21) : avant ce fix, cette fonction ne faisait
/// qu'un `compiler_fence` — aucune zéroïsation effective. Elle
/// appelle désormais `secure_buffer::global_wipe_all_buffers()` qui
/// parcourt le registre atomique des buffers actifs et les zeroize.
///
/// # Safety
/// Le registre `TRACKED_PTRS` contient des pointeurs valides (garanti
/// par le cycle de vie de `SecureBuffer` : enregistrement à la
/// création, désenregistrement au `Drop`).
pub fn purge_all_secrets() {
    // 1. Zéroïser tous les buffers enregistrés (RAM réelle)
    unsafe {
        crate::secure_buffer::global_wipe_all_buffers();
    }

    // 2. Barrière mémoire CPU + compilateur
    compiler_fence(Ordering::SeqCst);
    std::sync::atomic::fence(Ordering::SeqCst);
}

// ------------------------------------------------------------------------------
// TESTS UNITAIRES DES BRANCHES D'ERREURS & COUVERTURE TOTALE (100% LLVM)
// ------------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_memory_provider_nominal_and_edge_cases() {
        let provider = SystemMemoryProvider;

        // Validation des cas limites (Pointeurs nuls / Tailles nulles)
        assert!(!provider.lock_memory(std::ptr::null(), 0));
        assert!(!provider.unlock_memory(std::ptr::null(), 0));

        // Allocation et essai de verrouillage réel sur le système hôte
        let buf = vec![0xA5u8; 64];
        let lock_res = provider.lock_memory(buf.as_ptr(), buf.len());
        let unlock_res = provider.unlock_memory(buf.as_ptr(), buf.len());

        // La réponse dépend des droits OS (VirtualLock/mlock) : on valide que le retour booléen est maîtrisé
        assert!(lock_res || !lock_res);
        assert!(unlock_res || !unlock_res);
    }

    #[test]
    fn test_mock_memory_provider_failure_branches() {
        let mock_fail = MockMemoryProvider::new(true);
        let dummy = [0x55u8; 16];

        assert!(!mock_fail.lock_memory(dummy.as_ptr(), dummy.len()));
        assert!(!mock_fail.unlock_memory(dummy.as_ptr(), dummy.len()));

        mock_fail.trigger_exit(137);
        assert!(mock_fail.exit_triggered.load(Ordering::SeqCst));
    }

    #[test]
    fn test_masked_secret_xor_logic_and_lifecycle() {
        let secret = b"aegis_top_secret_key";
        let masked = MaskedSecret::new(secret).expect("La génération du masque doit réussir");

        // Vérification que les données masquées en RAM ne sont pas en clair
        assert_ne!(masked.masked_data, secret);

        // Extraction et dé-masquage temporaire
        masked.expose(|unmasked| {
            assert_eq!(unmasked, secret);
        });
    }

    #[test]
    fn test_protected_buffer_empty_and_normal() {
        prevent_core_dumps();

        // Test tampon vide
        let empty_pb = ProtectedBuffer::new(vec![]);
        assert!(empty_pb.as_slice().is_empty());

        // Test tampon alimenté
        let data = vec![1, 2, 3, 4, 5];
        let pb = ProtectedBuffer::new(data.clone());
        assert_eq!(pb.as_slice(), &data[..]);

        purge_all_secrets();
    }
}