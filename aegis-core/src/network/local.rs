use libp2p::{
    mdns,
    swarm::NetworkBehaviour,
    Swarm,
};
use std::error::Error;

#[derive(NetworkBehaviour)]
pub struct LocalBehaviour {
    pub mdns: mdns::tokio::Behaviour,
}

/// Initialise un Swarm libp2p configuré pour le réseau local via mDNS.
pub async fn create_local_swarm() -> Result<Swarm<LocalBehaviour>, Box<dyn Error>> {
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(), // CORRECTION : Instanciation avec ()
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let mdns = mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                key.public().to_peer_id(),
            )?;
            Ok(LocalBehaviour { mdns })
        })?
        .build();

    // Écoute sur toutes les interfaces IPv4 sur un port aléatoire
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    Ok(swarm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_swarm_creation() {
        let swarm = create_local_swarm().await;
        assert!(swarm.is_ok(), "L'initialisation du Swarm local mDNS a échoué");
    }
}