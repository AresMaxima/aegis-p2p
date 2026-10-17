//! aegis-core/src/network/dispatcher.rs
//!
//! P0-A.5b (2026-10-17) — Dispatcher réseau unifié.
//! Route les payloads applicatifs vers le bon transport (Tor, Wifi, BLE)
//! en appliquant le chiffrement Double Ratchet (D40).

use crate::crypto::ratchet::RatchetSession;
use crate::network::encrypted_transport::{EncryptedTransport, TransportError};
use crate::network::hopping::{RouteHandle, TransportSelector};

#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("no route available")]
    NoRoute,
}

/// Dispatcher générique pour permettre l'injection de mocks dans les tests.
pub struct Dispatcher<T, W, B>
where
    T: EncryptedTransport,
    W: EncryptedTransport,
    B: EncryptedTransport,
{
    selector: TransportSelector,
    tor_transport: T,
    wifi_transport: W,
    ble_transport: B,
}

impl<T, W, B> Dispatcher<T, W, B>
where
    T: EncryptedTransport,
    W: EncryptedTransport,
    B: EncryptedTransport,
{
    pub fn new(
        selector: TransportSelector,
        tor_transport: T,
        wifi_transport: W,
        ble_transport: B,
    ) -> Self {
        Self {
            selector,
            tor_transport,
            wifi_transport,
            ble_transport,
        }
    }

    /// Dispatch un payload vers le meilleur transport disponible.
    /// L'implémentation du transport est responsable d'appeler `session.encrypt()`.
    pub async fn dispatch(
        &self,
        session: &mut RatchetSession,
        payload: &[u8],
    ) -> Result<(), DispatchError> {
        // 1. Sélection de la route
        let candidate = self
            .selector
            .get_best_route()
            .await
            .ok_or(DispatchError::NoRoute)?;

        // 2. Aiguillage vers le transport typé
        match candidate.handle {
            RouteHandle::Tor { .. } => {
                self.tor_transport.send_encrypted(session, payload).await?;
            }
            RouteHandle::WifiDirect { .. } => {
                self.wifi_transport.send_encrypted(session, payload).await?;
            }
            RouteHandle::BleMesh { .. } => {
                self.ble_transport.send_encrypted(session, payload).await?;
            }
        }

        Ok(())
    }
}

// =========================================================================
// Tests
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::hopping::RouteCandidate;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

    // Mock d'un transport qui compte simplement les appels
    struct MockTransport {
        calls: Arc<AtomicUsize>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self { calls: Arc::new(AtomicUsize::new(0)) }
        }
    }

    #[allow(async_fn_in_trait)]
    impl EncryptedTransport for MockTransport {
        async fn send_encrypted(
            &self,
            _session: &mut RatchetSession,
            _plaintext: &[u8],
        ) -> Result<(), TransportError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn recv_decrypted(
            &self,
            _session: &mut RatchetSession,
        ) -> Result<Vec<u8>, TransportError> {
            Ok(vec![])
        }
    }

    /// Crée une RatchetSession valide en simulant un handshake X3DH local.
    fn dummy_session() -> RatchetSession {
        let static_a = X25519StaticSecret::random_from_rng(rand::rngs::OsRng);
        let ephemeral_a = X25519StaticSecret::random_from_rng(rand::rngs::OsRng);
        let static_b = X25519StaticSecret::random_from_rng(rand::rngs::OsRng);
        let ephemeral_b = X25519StaticSecret::random_from_rng(rand::rngs::OsRng);

        let pub_static_b = X25519PublicKey::from(&static_b);
        let pub_ephemeral_b = X25519PublicKey::from(&ephemeral_b);

        // On crée la session initiatrice (Alice) en pointant vers les clés de Bob
        RatchetSession::new_initiator(
            &static_a,
            &ephemeral_a,
            &pub_static_b,
            &pub_ephemeral_b,
        )
    }

    #[tokio::test]
    async fn test_dispatch_tor_route() {
        let selector = TransportSelector::new(60);
        selector
            .add_route(RouteCandidate {
                handle: RouteHandle::Tor {
                    address: "abc.onion".to_string(),
                    is_ephemeral: false,
                },
                priority: 50,
            })
            .await;

        let tor = MockTransport::new();
        let wifi = MockTransport::new();
        let ble = MockTransport::new();

        let tor_calls = Arc::clone(&tor.calls);

        let dispatcher = Dispatcher::new(selector, tor, wifi, ble);
        let mut session = dummy_session();

        let res = dispatcher.dispatch(&mut session, b"hello").await;
        assert!(res.is_ok());
        assert_eq!(tor_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_dispatch_wifi_route() {
        let selector = TransportSelector::new(60);
        selector
            .add_route(RouteCandidate {
                handle: RouteHandle::WifiDirect {
                    address: "192.168.49.1:8080".to_string(),
                },
                priority: 80,
            })
            .await;

        let tor = MockTransport::new();
        let wifi = MockTransport::new();
        let ble = MockTransport::new();

        let wifi_calls = Arc::clone(&wifi.calls);

        let dispatcher = Dispatcher::new(selector, tor, wifi, ble);
        let mut session = dummy_session();

        let res = dispatcher.dispatch(&mut session, b"hello").await;
        assert!(res.is_ok());
        assert_eq!(wifi_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_dispatch_ble_route() {
        let selector = TransportSelector::new(60);
        selector
            .add_route(RouteCandidate {
                handle: RouteHandle::BleMesh {
                    address: "AA:BB:CC:DD:EE:FF".to_string(),
                },
                priority: 90,
            })
            .await;

        let tor = MockTransport::new();
        let wifi = MockTransport::new();
        let ble = MockTransport::new();

        let ble_calls = Arc::clone(&ble.calls);

        let dispatcher = Dispatcher::new(selector, tor, wifi, ble);
        let mut session = dummy_session();

        let res = dispatcher.dispatch(&mut session, b"hello").await;
        assert!(res.is_ok());
        assert_eq!(ble_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_dispatch_no_route() {
        // Aucune route ajoutée
        let selector = TransportSelector::new(60);
        let tor = MockTransport::new();
        let wifi = MockTransport::new();
        let ble = MockTransport::new();

        let dispatcher = Dispatcher::new(selector, tor, wifi, ble);
        let mut session = dummy_session();

        let res = dispatcher.dispatch(&mut session, b"hello").await;
        assert!(matches!(res, Err(DispatchError::NoRoute)));
    }
}