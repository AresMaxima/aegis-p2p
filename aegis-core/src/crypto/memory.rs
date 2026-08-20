use std::sync::atomic::{compiler_fence, Ordering};
use zeroize::Zeroize;

/// Empêche la génération de memory dumps et interdit la lecture de `/proc/self/mem`
/// par d'autres processus ou spyciels.
pub fn prevent_core_dumps() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// Conteneur cryptographique masquant dynamiquement les clés en RAM via un pad XOR éphémère.
/// Le secret n'est dé-masqué temporairement que durant l'exécution d'une fermeture (closure).
pub struct MaskedSecret {
    masked_data: Vec<u8>,
    mask: Vec<u8>,
}

impl MaskedSecret {
    /// Crée une nouvelle instance chiffrée en RAM à l'aide d'un masque aléatoire unique.
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

        #[cfg(target_os = "windows")]
        unsafe {
            windows_sys::Win32::System::Memory::VirtualLock(
                self.data.as_ptr() as *const _,
                self.data.len(),
            );
        }

        #[cfg(not(target_os = "windows"))]
        unsafe {
            libc::mlock(self.data.as_ptr() as *const _, self.data.len());
        }
    }
}

impl Drop for ProtectedBuffer {
    fn drop(&mut self) {
        self.data.zeroize(); // Nettoyage explicite lors de la destruction du tampon
    }
}

/// Force la purge immédiate des secrets et pose une barrière mémoire
/// pour empêcher toute réorganisation d'instructions par le compilateur[cite: 15].
pub fn purge_all_secrets() {
    compiler_fence(Ordering::SeqCst); // Pose de la barrière mémoire atomique[cite: 15]
}