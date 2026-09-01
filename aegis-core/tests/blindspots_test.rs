use aegis_core::{
    crypto::{
        integrity::AegisIntegrityMonitor,
        keys::{derive_keys_from_mnemonic, generate_mnemonic},
        memory::{prevent_core_dumps, purge_all_secrets, MaskedSecret, ProtectedBuffer},
        ratchet::{pad_payload, unpad_payload},
        tpm::AegisTpmManager,
    },
    crypto_pq::HybridKeyExchange,
    deadman::DeadMansSwitch,
    ffi_security::execute_constant_time_ffi,
    hardware_triggers::HardwareTriggerMonitor,
    keystore::HardwareKeystore,
    mesh::SneakernetMesh,
    network::{
        dht::DhtBehaviour,
        hopping::TransportSelector,
        local::LocalBehaviour,
        p2p_transfer::MetadataStripper,
        tor::secure_wipe_dir,
    },
    panic::PanicPurge,
    polymorphic_ram::PolymorphicBuffer,
    secure_buffer::SecureBuffer,
    session::OpaqueSessionVault,
    signals::{setup_signal_handler, MemoryNoiseCanary},
    stegano::drowning::{extract_mnemonic_from_text, get_random_cover_poem, hide_mnemonic_in_text},
    storage::{db::AegisDatabase, vault::AegisVault},
    transport::{DynamicTransportRouter, TransportMode},
};

#[test]
fn test_blindspots_full_26_modules_sweep() {
    let mut sbuf = SecureBuffer::new(64);
    sbuf.as_slice_mut()[0] = 0xA5;
    let _ = sbuf.as_slice();

    let mut poly = PolymorphicBuffer::new(&[0xAA; 64]);
    let _ = poly.read_and_mutate();

    prevent_core_dumps();
    if let Ok(ms) = MaskedSecret::new(&[1, 2, 3, 4]) {
        ms.expose(|d| { let _ = d.len(); });
    }
    let pb = ProtectedBuffer::new(vec![1, 2, 3]);
    let _ = pb.as_slice();
    purge_all_secrets();

    let salt = [0u8; 16];
    if let Ok(mk) = AegisVault::derive_master_key(b"passphrase_test", &salt) {
        let mut sess = OpaqueSessionVault::new(mk.as_slice(), true);
        let _ = sess.get_key_temporary();
        let _ = sess.decrypt_in_place(&[0u8; 16]);

        if let Ok(db) = AegisDatabase::open_encrypted(":memory:", &mk) {
            let _ = db.secure_purge_table("logs");
        }
    }
    let _ = HardwareKeystore::get_or_create_root_key();

    DeadMansSwitch::set_max_inactivity(3600);
    DeadMansSwitch::heartbeat();

    let _ = std::mem::size_of::<HardwareTriggerMonitor>();
    let _ = std::mem::size_of::<PanicPurge>();

    AegisIntegrityMonitor::start();
    let _ = AegisIntegrityMonitor::check_debugger_present();
    let _ = AegisIntegrityMonitor::check_code_integrity();

    setup_signal_handler();
    let _canary = MemoryNoiseCanary::inject(1, 32);

    // --- CORRECTION DU MODULE CRYPTO_PQ ---
    let (pk, sk) = HybridKeyExchange::generate_keypair();
    let (_shared_sec, eph_pk, ct) =
        HybridKeyExchange::encapsulate_and_derive(&pk.x25519_pk, &pk.kyber_pk);

    let eph_sk = x25519_dalek::EphemeralSecret::random_from_rng(&mut rand::thread_rng());
    let _ = HybridKeyExchange::decapsulate_and_derive(eph_sk, &sk.kyber_sk, &eph_pk, &ct);
    // -------------------------------------

    if let Ok(m) = generate_mnemonic(12) {
        if let Ok(k) = derive_keys_from_mnemonic(&m) {
            let _ = k.ed25519_verifying();
            let _ = k.x25519_public();
            let _ = k.public_identity_hash();
        }
    }

    if let Ok(padded) = pad_payload(&[1, 2, 3], 16) {
        let _ = unpad_payload(&padded);
    }

    let _ = AegisTpmManager::verify_kernel_integrity();
    let _ = AegisTpmManager::unseal_master_secret(&[0u8; 32]);

    let _ = SneakernetMesh::ingest_packet([0u8; 512], 1);
    let _ = SneakernetMesh::export_gossip_bundle();

    let _dht_size = std::mem::size_of::<DhtBehaviour>();
    let _local_size = std::mem::size_of::<LocalBehaviour>();
    let _ts = TransportSelector::new(30);

    let tmp_dir = std::env::temp_dir().join("aegis_tor_test_bs");
    let _ = std::fs::create_dir_all(&tmp_dir);
    secure_wipe_dir(&tmp_dir);

    let poem = get_random_cover_poem();
    if let Ok(stego) = hide_mnemonic_in_text("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", Some(poem)) {
        let _ = extract_mnemonic_from_text(&stego);
    }

    let _ = execute_constant_time_ffi(1, || 42);

    let _ = MetadataStripper::detect_type(&[0xFF, 0xD8, 0xFF]);
    let _ = MetadataStripper::strip_and_normalize(&sbuf);

    let mut router = DynamicTransportRouter::new(TransportMode::DirectWan);
    let _ = router.current_mode();
    router.set_mode(TransportMode::DirectWan);
    let _ = router.evaluate_and_hop(true, true);
}