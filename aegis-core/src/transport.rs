#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    TorEmbedded,
    DirectWan,
    LocalAirGapped,
    HybridAutoHopping,
}

pub struct DynamicTransportRouter {
    current_mode: TransportMode,
}

impl DynamicTransportRouter {
    pub fn new(initial_mode: TransportMode) -> Self {
        Self {
            current_mode: initial_mode,
        }
    }

    /// Renvoie le mode de transport configuré par l'utilisateur
    pub fn current_mode(&self) -> TransportMode {
        self.current_mode
    }

    /// Modifie le mode de transport de manière dynamique à chaud
    pub fn set_mode(&mut self, mode: TransportMode) {
        self.current_mode = mode;
    }

    /// Analyse la connectivité et détermine le meilleur vecteur de transport sans modifier la configuration racine
    pub fn evaluate_and_hop(&self, is_internet_available: bool, is_tor_reachable: bool) -> TransportMode {
        if self.current_mode == TransportMode::HybridAutoHopping {
            if is_internet_available && is_tor_reachable {
                TransportMode::TorEmbedded
            } else if is_internet_available {
                TransportMode::DirectWan
            } else {
                TransportMode::LocalAirGapped
            }
        } else {
            self.current_mode
        }
    }
}

// =========================================================================
// TESTS UNITAIRES (Couverture Totale 100% LLVM)
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_creation_and_mutations() {
        let mut router = DynamicTransportRouter::new(TransportMode::DirectWan);
        assert_eq!(router.current_mode(), TransportMode::DirectWan);

        router.set_mode(TransportMode::TorEmbedded);
        assert_eq!(router.current_mode(), TransportMode::TorEmbedded);
    }

    #[test]
    fn test_evaluate_and_hop_fixed_modes() {
        // Test que les modes stricts ne changent jamais, peu importe l'état du réseau
        let router_local = DynamicTransportRouter::new(TransportMode::LocalAirGapped);
        assert_eq!(router_local.evaluate_and_hop(true, true), TransportMode::LocalAirGapped);
        assert_eq!(router_local.evaluate_and_hop(false, false), TransportMode::LocalAirGapped);

        let router_tor = DynamicTransportRouter::new(TransportMode::TorEmbedded);
        assert_eq!(router_tor.evaluate_and_hop(false, false), TransportMode::TorEmbedded);
    }

    #[test]
    fn test_evaluate_and_hop_hybrid_auto_hopping() {
        let router = DynamicTransportRouter::new(TransportMode::HybridAutoHopping);

        // Branche 1 : Internet OK + Tor OK -> Priorité absolue à Tor
        assert_eq!(router.evaluate_and_hop(true, true), TransportMode::TorEmbedded);

        // Branche 2 : Internet OK + Tor DOWN -> Repli sur DirectWan (ClearNet sécurisé)
        assert_eq!(router.evaluate_and_hop(true, false), TransportMode::DirectWan);

        // Branche 3 : Internet DOWN -> Repli ultime sur Air-Gapped / Réseau local
        assert_eq!(router.evaluate_and_hop(false, false), TransportMode::LocalAirGapped);
        
        // Cas extrême : Internet DOWN mais Tor signalé comme atteignable (impossible physiquement, mais valide la robustesse logique)
        assert_eq!(router.evaluate_and_hop(false, true), TransportMode::LocalAirGapped);
    }

    #[test]
    fn test_transport_mode_traits() {
        // Couverture métrique pour les traits générés automatiquement (Debug, Clone, PartialEq, Eq)
        let mode1 = TransportMode::HybridAutoHopping;
        let mode2 = mode1.clone();
        
        assert_eq!(mode1, mode2);
        assert_ne!(mode1, TransportMode::TorEmbedded);
        
        // S'assure que le Debug formatter fonctionne (LLVM coverage)
        let debug_str = format!("{:?}", mode1);
        assert_eq!(debug_str, "HybridAutoHopping");
    }
}