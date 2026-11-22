#![cfg(not(miri))]

use aegis_core::{
    attestation::compute_peer_attestation_challenge,
    crypto::{
        integrity::AegisIntegrityMonitor,
        keys::{derive_keys_from_mnemonic, generate_mnemonic},
        memory::{prevent_core_dumps, purge_all_secrets, MaskedSecret, ProtectedBuffer},
        ratchet::{pad_payload, unpad_payload},
    },
    crypto_pq::HybridKeyExchange,
    deadman::DeadMansSwitch,
    ffi_security::execute_constant_time_ffi,
    hardware_triggers::HardwareTriggerMonitor,
    keystore::HardwareKeystore,
    mesh::SneakernetMesh,
    network::{
        chaffing::{ChaffScheduler, WireCell512, WireCellKind},
        dead_drop::{derive_hourly_blind_tag, fragment_for_lora_relay, RamDeadDropVault},
        hopping::TransportSelector,
        optical_fountain::{encode_optical_fountain_stream, OpticalFountainDecoder},
        p2p_transfer::MetadataStripper,
        tor::secure_wipe_dir,
    },
    panic::PanicPurge,
    polymorphic_ram::PolymorphicBuffer,
    secure_buffer::SecureBuffer,
    session::OpaqueSessionVault,
    signals::{setup_signal_handler, MemoryNoiseCanary},
    stegano::drowning::{extract_mnemonic_from_text, get_random_cover_poem, hide_mnemonic_in_text},
    storage::vault::AegisVault,
    transport::{DynamicTransportRouter, TransportMode},
};

#[cfg(feature = "tpm")]
use aegis_core::crypto::tpm::AegisTpmManager;

#[test]
fn test_blindspots_full_v36_modules_sweep() {
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

    // Vraie dérivation matérielle HardwareKeystore (remplace l'ancien stub SQLite/Vault)
    let _ = HardwareKeystore::set_root_key(&[0x55u8; 32]);
    if HardwareKeystore::derive_master_key("BlindspotPIN-v36").is_ok() {
        if let Ok(mk) = HardwareKeystore::get_master_key() {
            let mut sess = OpaqueSessionVault::new(mk.as_slice(), true);
            let _ = sess.get_key_temporary();
            let _ = sess.decrypt_in_place(&[0u8; 16]);
        }
    }
    let tmp_vault_file = std::env::temp_dir().join("aegis_bs_wipe.tmp");
    let _ = AegisVault::purge(&tmp_vault_file);

    // Couverture des modules v3.6 (C90 Chaffing, C91 Mutual Attest, C92 Optical, C93 Dead-Drop/LoRa)
    let mut chaff = ChaffScheduler::new(250);
    chaff.configure(true, 250);
    let _ = chaff.enqueue(WireCellKind::LiveMessage, b"BS_PING");
    if let Ok(Some(cell)) = chaff.poll_tick(true) {
        let _ = cell.unpack();
    }
    let _ = WireCell512::new_chaff();
    chaff.wipe();

    let _att_chal = compute_peer_attestation_challenge(&[0x11u8; 32], &[0x22u8; 32]);

    let tag = derive_hourly_blind_tag(&[0x33u8; 32], 12345);
    let mut dd = RamDeadDropVault::new(16, 600);
    let _ = dd.deposit(tag, vec![0xAA; 64]);
    let _ = dd.collect_and_burn(&tag);
    let _ = fragment_for_lora_relay([1; 8], 4, true, &[0xBB; 300]);

    if let Ok(frames) = encode_optical_fountain_stream([9, 8, 7, 6], &[0xCC; 200]) {
        let mut dec = OpticalFountainDecoder::default();
        for f in &frames {
            if dec.ingest_wire_droplet(f).unwrap_or(false) {
                let _ = dec.finalize_and_wipe();
                break;
            }
        }
    }

    DeadMansSwitch::set_max_inactivity(3600);
    DeadMansSwitch::heartbeat();

    let _ = std::mem::size_of::<HardwareTriggerMonitor>();
    let _ = std::mem::size_of::<PanicPurge>();

    AegisIntegrityMonitor::start();
    let _ = AegisIntegrityMonitor::check_debugger_present();
    let _ = AegisIntegrityMonitor::check_code_integrity();

    setup_signal_handler();
    let _canary = MemoryNoiseCanary::inject(1, 32);

    let (sk, pk) = HybridKeyExchange::generate_keypair();
    let recv_eph_sk = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
    let recv_eph_pk = x25519_dalek::PublicKey::from(&recv_eph_sk);
    let (_shared_sec, eph_pk, ct) = HybridKeyExchange::encapsulate_and_derive(&recv_eph_pk, &sk.kyber_pk);
    let _ = HybridKeyExchange::decapsulate_and_derive(recv_eph_sk, &pk.kyber_sk, &eph_pk, &ct);

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

    #[cfg(feature = "tpm")]
    {
        let _ = AegisTpmManager::verify_kernel_integrity();
        let _ = AegisTpmManager::unseal_master_secret(&[0u8; 32]);
    }

    let _ = SneakernetMesh::ingest_packet([0u8; 512], 1);
    let _ = SneakernetMesh::export_gossip_bundle();

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