use libp2p::{
    mdns,
    swarm::NetworkBehaviour,
    PeerId, Swarm,
};
use std::error::Error;

#[derive(NetworkBehaviour)]
pub struct LocalBehaviour {
    pub mdns: mdns::tokio::Behaviour,
}

/// Initialise un Swarm libp2p configuré pour la découverte locale (mDNS).
pub async fn create_local_swarm() -> Result<(PeerId, Swarm<LocalBehaviour>), Box<dyn Error>> {
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let local_peer_id = key.public().to_peer_id();
            let mdns_config = mdns::Config::default();
            let mdns = mdns::tokio::Behaviour::new(mdns_config, local_peer_id)?;
            Ok(LocalBehaviour { mdns })
        })?
        .build();

    let local_peer_id = *swarm.local_peer_id();
    
    // Écoute standard TCP
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    Ok((local_peer_id, swarm))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Demande à Miri d'ignorer la création de sockets réseau bas niveau
    async fn test_local_swarm_creation() {
        let result = create_local_swarm().await;
        assert!(result.is_ok(), "L'initialisation de la découverte mDNS a échoué");
        
        let (peer_id, _swarm) = result.unwrap();
        assert_ne!(peer_id.to_string(), "");
    }
}