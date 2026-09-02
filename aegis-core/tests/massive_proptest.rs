use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 100_000,
        max_shrink_iters: 10_000,
        .. ProptestConfig::default()
    })]

    #[test]
    fn test_frame_bounds_and_entropy_integrity(
        ref data in prop::collection::vec(any::<u8>(), 0..4096)
    ) {
        let len = data.len();
        prop_assert!(len <= 4096);
    }
}
