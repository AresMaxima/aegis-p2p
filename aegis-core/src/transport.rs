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