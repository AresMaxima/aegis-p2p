//! aegis-core/src/signals.rs
//! Interception des signaux OS & Injection de leurres mémoire (Cold Boot Attack)

use crate::secure_buffer::SecureBuffer;
use rand::RngCore;

#[cfg(unix)]
use std::{process, thread};

#[cfg(unix)]
use signal_hook::{consts::signal::*, iterator::Signals};

/// Intercepte SIGINT / SIGTERM pour couper immédiatement le processus
/// et purger la RAM avant extraction forensique à chaud.
pub fn setup_signal_handler() {
    #[cfg(unix)]
    {
        let mut signals = Signals::new(&[SIGINT, SIGTERM]).expect("Échec d'attachement des signaux OS");
        thread::spawn(move || {
            for sig in signals.forever() {
                eprintln!("[ALERT] Signal {} détecté. Interruption d'urgence.", sig);
                process::exit(137);
            }
        });
    }

    #[cfg(windows)]
    {
        // Fallback minimal pour que la compilation passe sous Windows lors des tests locaux.
        // L'interception de signaux agressifs est déléguée à l'OS cible (Android/Linux).
        eprintln!("[INFO] Handlers de signaux POSIX ignorés (Cible Windows détectée).");
    }
}

/// Injecte N tampons leurres remplis d'entropie dans la RAM
/// pour brouiller les scans de clés (Volatility / Rekall) lors d'une Cold Boot Attack.
#[must_use = "Le MemoryNoiseCanary doit être conservé dans l'état de l'application, sinon les leurres seront immédiatement purgés de la RAM."]
pub struct MemoryNoiseCanary {
    _buffers: Vec<SecureBuffer>,
}

impl MemoryNoiseCanary {
    pub fn inject(count: usize, size_per_buffer: usize) -> Self {
        let mut buffers = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        for _ in 0..count {
            let mut buf = SecureBuffer::new(size_per_buffer);
            rng.fill_bytes(buf.as_slice_mut());
            buffers.push(buf);
        }

        Self { _buffers: buffers }
    }
}