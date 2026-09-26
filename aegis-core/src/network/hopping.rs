//! aegis-core/src/network/hopping.rs
//! Routage Hopping Dynamique Multi-Transports & Générateur de Trafic Leurre (Chaff) - CdCM v2.2-RC1.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    LocalLan,
    P2pDht,
    TorOnion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCandidate {
    pub transport: TransportType,
    pub address: String,
    pub priority: u8,
    pub is_ephemeral: bool,
}

/// Sélecteur de route dynamique gérant l'ordre des transports et la bascule à chaud
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
                if let Some(tor_route) = guards
                    .iter_mut()
                    .find(|c| c.transport == TransportType::TorOnion && c.is_ephemeral)
                {
                    tor_route.address = new_onion_address;
                }
            }
        });
    }
}

/// Générateur de trafic leurre réseau (Chaff Traffic Generator)
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

    #[test]
    fn test_hopping_guard_reorder() {
        let mut guards = vec![
            HoppingGuard { id: 1, priority: 5 },
            HoppingGuard { id: 2, priority: 10 },
            HoppingGuard { id: 3, priority: 1 },
        ];
        TransportHoppingRouter::reorder_guards(&mut guards);
        assert_eq!(guards[0].priority, 10);
        assert_eq!(guards[1].priority, 5);
        assert_eq!(guards[2].priority, 1);
    }

    #[tokio::test]
    async fn test_transport_hopping_selection() {
        let selector = TransportSelector::new(300);

        selector
            .add_route(RouteCandidate {
                transport: TransportType::P2pDht,
                address: "/ip4/192.168.1.50/tcp/4001".to_string(),
                priority: 5,
                is_ephemeral: false,
            })
            .await;

        selector
            .add_route(RouteCandidate {
                transport: TransportType::LocalLan,
                address: "/ip4/192.168.1.50/tcp/5000".to_string(),
                priority: 10,
                is_ephemeral: false,
            })
            .await;

        selector
            .add_route(RouteCandidate {
                transport: TransportType::TorOnion,
                address: "aegis_ephemeral_1.onion:9050".to_string(),
                priority: 2,
                is_ephemeral: true,
            })
            .await;

        let best = selector.get_best_route().await.unwrap();
        assert_eq!(best.transport, TransportType::LocalLan);

        let next = selector.fallback_next().await.unwrap();
        assert_eq!(next.transport, TransportType::P2pDht);

        let tor = selector.fallback_next().await.unwrap();
        assert_eq!(tor.transport, TransportType::TorOnion);
        assert!(tor.is_ephemeral);
    }

    #[tokio::test]
    async fn test_chaff_traffic_generation() {
        let packet_count = Arc::new(AtomicUsize::new(0));
        let packet_count_clone = Arc::clone(&packet_count);

        // Lance un générateur de leurres ultra-rapide (1 à 2 secondes) pour le test
        ChaffTrafficGenerator::spawn_chaff_loop(
            move |packet| {
                let count = Arc::clone(&packet_count_clone);
                async move {
                    assert_eq!(packet.len(), 528); // Vérification de la taille standard matelassée
                    count.fetch_add(1, Ordering::SeqCst);
                }
            },
            1,
            2,
        );

        // Attend 2.5 secondes pour vérifier qu'au moins un paquet leurre a été généré
        sleep(Duration::from_millis(2500)).await;
        assert!(packet_count.load(Ordering::SeqCst) >= 1);
    }
}