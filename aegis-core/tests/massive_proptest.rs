use proptest::prelude::*;
use aegis_core::crypto_pq::process_512b_frame_ephemeral;

proptest! {
    // Configuration poussée à 1 000 000 de cas de test avec mutations complexes
    #![proptest_config(ProptestConfig::with_cases(1000000))]
    #[test]
    fn fuzz_ephemeral_frame_million(
        master_key in prop::collection::vec(any::<u8>(), 32),
        frame_index in any::<u64>(),
        payload in prop::collection::vec(any::<u8>(), 512),
        mutation_mask in any::<u8>()
    ) {
        let mut frame = [0u8; 512];
        frame.copy_from_slice(&payload);
        
        let mut frame_work = frame;

        // 1. Ingestion du bloc chiffré (Chiffrement In-Place)
        let res = process_512b_frame_ephemeral(&master_key, frame_index, &mut frame_work);
        prop_assert!(res.is_ok());

        // 2. Test d'intégrité sous mutation vs Propriété involutive
        if mutation_mask > 200 {
            // Mutation garantie d'au moins un bit (mutation_mask > 200 implique mutation_mask != 0)
            frame_work[0] ^= mutation_mask;
            let res_corrupted = process_512b_frame_ephemeral(&master_key, frame_index, &mut frame_work);
            
            // La dérivation sur trame corrompue doit échouer ou produire un résultat altéré
            prop_assert!(res_corrupted.is_err() || frame_work != frame);
        } else {
            // 3. Déchiffrement In-Place (Vérification de la propriété involutive)
            let res_back = process_512b_frame_ephemeral(&master_key, frame_index, &mut frame_work);
            prop_assert!(res_back.is_ok());
            prop_assert_eq!(frame_work, frame);
        }
    }
}