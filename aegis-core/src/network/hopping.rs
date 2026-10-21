//! aegis-core/src/network/hopping.rs
//! Routage Hopping Dynamique Multi-Transports & Générateur de Trafic Leurre (Chaff) - CdCM v2.2-RC1.
//!
//! P0-A.5a (2026-10-17) — Introduction de RouteHandle typé (D100).
//! P0-A.5a+ (2026-10-22) — Refactor C110 : newtypes typés (TorAddress, WifiDirectAddress,
//! BleMeshAddress) pour remplacer les String nus. La compilation empêche désormais
//! de passer une IP à un RouteHandle::Tor.

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
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

// ─────────────────────────────────────────────────────────────────────
// Newtypes typés pour RouteHandle (C110)
// ─────────────────────────────────────────────────────────────────────

/// Adresse Tor v3 (.onion). Format strict :
///   • <56 chars base32>.onion (v3 = 56 chars)
///   • <16 chars base32>.onion (v2 legacy, déprécié mais accepté en lecture)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorAddress(String);

impl TorAddress {
    /// Constructeur validant le format .onion.
    pub fn new(addr: impl Into<String>) -> Result<Self, &'static str> {
        let s = addr.into();
        if !s.ends_with(".onion") {
            return Err("Tor address must end with .onion");
        }
        let host = &s[..s.len() - 6];
        if host.len() != 56 && host.len() != 16 {
            return Err("Tor v3 host must be 56 chars, v2 = 16");
        }
        if !host.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err("Tor host must be base32 alphanumeric");
        }
        Ok(Self(s))
    }

    /// Constructeur non-validant, réservé aux tests.
    #[cfg(test)]
    pub fn new_unchecked(addr: impl Into<String>) -> Self {
        Self(addr.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_ephemeral(&self) -> bool {
        // Heuristique : toutes les adresses Tor v3 sont "ephemeral" par défaut
        // dans AEGIS (rotation de circuit). Surchargeable côté appelant.
        self.0.len() == 62 // .onion v3 = 56 + 6
    }
}

impl fmt::Display for TorAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Adresse Wi-Fi Direct (socket TCP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiDirectAddress(SocketAddr);

impl WifiDirectAddress {
    pub fn new(addr: SocketAddr) -> Self {
        Self(addr)
    }

    /// Parse une chaîne "IP:Port" — pour la compatibilité des tests.
    pub fn parse(s: &str) -> Result<Self, std::net::AddrParseError> {
        Ok(Self(s.parse::<SocketAddr>()?))
    }

    pub fn as_socket_addr(&self) -> SocketAddr {
        self.0
    }
}

impl fmt::Display for WifiDirectAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Adresse BLE Mesh (MAC 48-bit ou UUID).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleMeshAddress(String);

impl BleMeshAddress {
    pub fn new(addr: impl Into<String>) -> Result<Self, &'static str> {
        let s = addr.into();
        // MAC : "AA:BB:CC:DD:EE:FF" (17 chars)
        // UUID : 36 chars avec tirets
        let valid_mac = s.len() == 17
            && s.chars().enumerate().all(|(i, c)| {
                if i % 3 == 2 { c == ':' } else { c.is_ascii_hexdigit() }
            });
        let valid_uuid = s.len() == 36
            && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
        if !valid_mac && !valid_uuid {
            return Err("BLE address must be MAC (AA:BB:...) or UUID");
        }
        Ok(Self(s))
    }

    #[cfg(test)]
    pub fn new_unchecked(addr: impl Into<String>) -> Self {
        Self(addr.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BleMeshAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Handle typé vers une route de transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteHandle {
    Tor {
        address: TorAddress,
        is_ephemeral: bool,
    },
    WifiDirect {
        address: WifiDirectAddress,
    },
    BleMesh {
        address: BleMeshAddress,
    },
}

impl RouteHandle {
    /// Retourne une représentation textuelle du handle (pour logging uniquement).
    /// Utilise un buffer `String` — ne jamais reconstruire un `RouteHandle` à partir
    /// de cette sortie (perte de typage).
    pub fn display_address(&self) -> String {
        match self {
            RouteHandle::Tor { address, .. } => address.to_string(),
            RouteHandle::WifiDirect { address } => address.to_string(),
            RouteHandle::BleMesh { address } => address.to_string(),
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
                let new_onion_str = on_circuit_rotate().await;
                // On suppose que la closure retourne une chaîne valide. En prod, il faudra
                // utiliser TorAddress::new() et gérer l'erreur. On garde new_unchecked pour
                // la simplicité du refactor actuel.
                let new_onion_address = match TorAddress::new(&new_onion_str) {
                    Ok(a) => a,
                    Err(_) => continue, // Ignore les adresses invalides (fail-closed)
                };

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
            handle: RouteHandle::Tor {
                address: TorAddress::new_unchecked("abc.onion"),
                is_ephemeral: false,
            },
            priority: 50,
        }).await;

        selector.add_route(RouteCandidate {
            handle: RouteHandle::WifiDirect {
                address: WifiDirectAddress::parse("192.168.49.1:8080").unwrap(),
            },
            priority: 80, // Priorité plus haute
        }).await;

        // 2. Le meilleur doit être Wi-Fi Direct (priorité 80)
        let best = selector.get_best_route().await.unwrap();
        assert_eq!(best.handle.display_address(), "192.168.49.1:8080");

        // 3. Fallback vers Tor
        let next = selector.fallback_next().await.unwrap();
        assert_eq!(next.handle.display_address(), "abc.onion");

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