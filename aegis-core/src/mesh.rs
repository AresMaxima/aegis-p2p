use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

const MAX_STORED_PACKETS: usize = 100;
const MAX_HOPS: u8 = 10;

#[derive(Clone)]
pub struct MeshPacket {
    pub payload: [u8; 512],
    pub hop_count: u8,
}

lazy_static::lazy_static! {
    static ref MESH_STORE: Mutex<HashMap<[u8; 32], MeshPacket>> = Mutex::new(HashMap::new());
}

pub struct SneakernetMesh;

impl SneakernetMesh {
    /// Calcule le Hash SHA-256 unique d'un paquet de 512 octets
    fn compute_id(frame: &[u8; 512]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(frame);
        hasher.finalize().into()
    }

    /// Ingère un paquet transmis de proche en proche par un pair BLE/Wi-Fi Direct
    pub fn ingest_packet(frame: [u8; 512], current_hops: u8) -> bool {
        if current_hops >= MAX_HOPS {
            return false; // Rejet : Durée de vie (TTL) expirée
        }

        let id = Self::compute_id(&frame);
        if let Ok(mut store) = MESH_STORE.lock() {
            if store.contains_key(&id) {
                return false; // Paquet déjà en mémoire (anti-boucle)
            }

            if store.len() >= MAX_STORED_PACKETS {
                // Purge du plus ancien élément si le tampon RAM est saturé
                if let Some(first_key) = store.keys().next().cloned() {
                    store.remove(&first_key);
                }
            }

            store.insert(id, MeshPacket {
                payload: frame,
                hop_count: current_hops + 1,
            });
            return true;
        }
        false
    }

    /// Récupère la liste de tous les paquets en attente pour les diffuser aux pairs environnants
    pub fn export_gossip_bundle() -> Vec<([u8; 512], u8)> {
        if let Ok(store) = MESH_STORE.lock() {
            store.values().map(|p| (p.payload, p.hop_count)).collect()
        } else {
            Vec::new()
        }
    }
}

/// Point d'entrée FFI pour ingérer une trame reçue via le canal BLE/Wi-Fi de l'appareil
#[no_mangle]
pub unsafe extern "C" fn aegis_mesh_ingest_frame(frame_ptr: *const u8, hops: u8) -> i32 {
    if frame_ptr.is_null() {
        return -1;
    }
    let slice = std::slice::from_raw_parts(frame_ptr, 512);
    let mut frame = [0u8; 512];
    frame.copy_from_slice(slice);

    if SneakernetMesh::ingest_packet(frame, hops) {
        0
    } else {
        -1
    }
}