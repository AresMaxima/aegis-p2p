//! aegis-core/src/network/hopping.rs
//! Routage Hopping Dynamique Multi-Transports & Générateur de Trafic Leurre (Chaff) - CdCM v2.2-RC1.
//!
//! P0-A.5a (2026-10-17) — Introduction de RouteHandle typé (D100).
//! Remplace l'ancien TransportType qui référençait encore P2pDht (supprimé D47)
//! et isole l'adresse au sein de chaque variante.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;

pub struct HoppingGuard {
    pub id: u64,
    pub priority: u32,
}

pub struct TransportHoppingRouter;

impl TransportHoppingRouter {
    pub fn reorder_guards(guards: &mut [HoppingGuard]) {
        guards.sort_by_key(|b| std::cmp::Reverse(b.priority));
    }
}

/// D100 (P0-A.5a) — Handle typé pour remplacer `address: String`.
/// Chaque variante porte l'adresse spécifique à son transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteHandle {
    /// Tor .onion address. Le booléen indique si le circuit doit être
    /// renouvelé périodiquement (rotation de circuit).
    Tor { address: String, is_ephemeral: bool },
    /// Wi-Fi Direct (IP:Port du socket TCP).
    WifiDirect { address: String },
    /// BLE Mesh (identifiant de device ou UUID).
    BleMesh { address: String },
}

impl RouteHandle {
    /// Récupère l'adresse sous forme de slice pour le logging ou la connexion.
    pub fn address(&self) -> &str {
        match self {
            RouteHandle::Tor { address, .. } => address,
            RouteHandle::WifiDirect { address } => address,
            RouteHandle::BleMesh { address } => address,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCandidate {
    pub handle: RouteHandle,
    pub priority: u8,
}

/// Sélecteur de route dynamique gérant l'ordre des transports et la bascule à chaud.
pub struct TransportSelector {
    candidates: Arc<RwLock<Vec<RouteCandidate>>>,
    rotation_interval: Duration,
}

impl TransportSelector {
    pub fn new(rotation_secs: u64) -> Self {
        Self {
            candidates: Arc::new(RwLock::new(Vec::new())),
            rotation_interval: Duration::from_secs(rotation_secs),
        }
    }

    pub async fn add_route(&self, candidate: RouteCandidate) {
        let mut guards = self.candidates.write().await;
        guards.push(candidate);
        guards.sort_by_key(|b| std::cmp::Reverse(b.priority));
    }

    pub async fn get_best_route(&self) -> Option<RouteCandidate> {
        let guards = self.candidates.read().await;
        guards.first().cloned()
    }

    pub async fn fallback_next(&self) -> Option<RouteCandidate> {
        let mut guards = self.candidates.write().await;
        if !guards.is_empty() {
            guards.remove(0);
        }
        guards.first().cloned()
    }

    /// Démarre la boucle de rotation des circuits en tâche de fond (Tokio Spawn).
    /// La closure est asynchrone pour ne pas bloquer le verrou pendant la négociation réseau.
    pub fn spawn_hopping_loop<F, Fut>(&self, mut on_circuit_rotate: F)
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = String> + Send + 'static,
    {
        let candidates_clone = Arc::clone(&self.candidates);
        let interval = self.rotation_interval;

        tokio::spawn(async move {
            loop {
                sleep(interval).await;

                // 1. Génération de la nouvelle adresse .onion en I/O asynchrone (hors verrou)
                let new_onion_address = on_circuit_rotate().await;

                // 2. Mise à jour éphémère sous verrou en microseconde
                let mut guards = candidates_clone.write().await;
                
                // On cherche la route Tor marquée comme éphémère (celle qui subit la rotation)
                if let Some(tor_route) = guards.iter_mut().find(|c| {
                    matches!(c.handle, RouteHandle::Tor { is_ephemeral: true, .. })
                }) {
                    if let RouteHandle::Tor { ref mut address, .. } = tor_route.handle {
                        *address = new_onion_address;
                    }
                }
            }
        });
    }
}

/// Générateur de trafic leurre réseau (Chaff Traffic Generator).
/// Injecte des paquets factices matelassés à intervalles aléatoires (jitter)
/// pour contrecarrer l'inspection de paquets (DPI) et l'analyse statistique de trafic.
pub struct ChaffTrafficGenerator;

impl ChaffTrafficGenerator {
    /// Lance la tâche Tokio de fond d'envoi de paquets leurres.
    /// - `send_callback`: closure asynchrone chargée d'expédier le paquet sur le réseau.
    /// - `min_delay_sec` / `max_delay_sec`: plage du délai aléatoire entre deux envois.
    pub fn spawn_chaff_loop<F, Fut>(
        mut send_callback: F,
        min_delay_sec: u64,
        max_delay_sec: u64,
    ) where
        F: FnMut(Vec<u8>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        tokio::spawn(async move {
            loop {
                // 1. Calcul d'un délai pseudo-aléatoire sécurisé (Jittering)
                let mut rand_bytes = [0u8; 2];
                let _ = getrandom::getrandom(&mut rand_bytes);

                let range = if max_delay_sec > min_delay_sec {
                    max_delay_sec - min_delay_sec
                } else {
                    1
                };

                let random_val = u16::from_be_bytes(rand_bytes) as u64;
                let delay_secs = min_delay_sec + (random_val % range);

                sleep(Duration::from_secs(delay_secs)).await;

                // 2. Génération d'un paquet factice de taille fixe (528 octets) rempli de bruit aléatoire
                let mut dummy_packet = vec![0u8; 528];
                let _ = getrandom::getrandom(&mut dummy_packet);

                // 3. Expédition asynchrone du paquet leurre
                send_callback(dummy_packet).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_hopping_guard_reorder() {
        let mut guards = vec![
            HoppingGuard { id: 1, priority: 10 },
            HoppingGuard { id: 2, priority: 30 },
            HoppingGuard { id: 3, priority: 20 },
        ];

        TransportHoppingRouter::reorder_guards(&mut guards);
        assert_eq!(guards[0].id, 2); // Priority 30
        assert_eq!(guards[1].id, 3); // Priority 20
        assert_eq!(guards[2].id, 1); // Priority 10
    }

    #[tokio::test]
    async fn test_transport_hopping_selection() {
        let selector = TransportSelector::new(60);

        // 1. Ajout de routes avec différents handles
        selector.add_route(RouteCandidate {
            handle: RouteHandle::Tor { address: "abc.onion".to_string(), is_ephemeral: false },
            priority: 50,
        }).await;

        selector.add_route(RouteCandidate {
            handle: RouteHandle::WifiDirect { address: "192.168.49.1:8080".to_string() },
            priority: 80, // Priorité plus haute
        }).await;

        // 2. Le meilleur doit être Wi-Fi Direct (priorité 80)
        let best = selector.get_best_route().await.unwrap();
        assert_eq!(best.handle.address(), "192.168.49.1:8080");

        // 3. Fallback vers Tor
        let next = selector.fallback_next().await.unwrap();
        assert_eq!(next.handle.address(), "abc.onion");

        // 4. Plus de route
        assert!(selector.fallback_next().await.is_none());
    }

    #[tokio::test]
    async fn test_chaff_traffic_generation() {
        use std::time::Duration;
        
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        // On lance le générateur avec des délais très courts (0 à 1 sec)
        ChaffTrafficGenerator::spawn_chaff_loop(
            move |packet| {
                let c = Arc::clone(&counter_clone);
                async move {
                    // Vérifie la taille fixe du paquet leurre
                    assert_eq!(packet.len(), 528);
                    c.fetch_add(1, Ordering::SeqCst);
                }
            },
            0, 1
        );

        // On attend 2.5 secondes pour laisser passer au moins 2 paquets
        tokio::time::sleep(Duration::from_millis(2500)).await;
        
        let count = counter.load(Ordering::SeqCst);
        assert!(count >= 2, "Au moins 2 paquets chaff attendus, reçu {}", count);
    }
}