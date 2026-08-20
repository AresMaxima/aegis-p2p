use libp2p::{
    kad::{self, store::MemoryStore, Config as KadConfig},
    swarm::NetworkBehaviour,
    PeerId, StreamProtocol, Swarm,
};
use std::error::Error;

#[derive(NetworkBehaviour)]
pub struct DhtBehaviour {
    pub kademlia: kad::Behaviour<MemoryStore>,
}

/// Initialise un Swarm libp2p configuré avec la DHT Kademlia SOUVERAINE pour AEGIS.
pub async fn create_dht_swarm() -> Result<(PeerId, Swarm<DhtBehaviour>), Box<dyn Error>> {
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(), // Instanciation directe de la configuration TCP
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let peer_id = key.public().to_peer_id();
            let store = MemoryStore::new(peer_id);
            
            // CORRECTION OPSEC : Isolement total du réseau DHT
            let mut cfg = KadConfig::default();
            // On utilise StreamProtocol pour libp2p 0.53+
            cfg.set_protocol_names(vec![StreamProtocol::new("/aegis/kad/1.0.0")]);

            let kademlia = kad::Behaviour::with_config(peer_id, store, cfg);
            Ok(DhtBehaviour { kademlia })
        })?
        .build();

    let local_peer_id = *swarm.local_peer_id();
    
    // Écoute sur toutes les interfaces locales sur un port TCP aléatoire
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    Ok((local_peer_id, swarm))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dht_swarm_creation() {
        let result = create_dht_swarm().await;
        assert!(result.is_ok(), "L'initialisation de la DHT Kademlia a échoué");
        
        let (peer_id, _swarm) = result.unwrap();
        assert_ne!(peer_id.to_string(), "");
    }
}