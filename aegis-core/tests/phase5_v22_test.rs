#[cfg(test)]
mod tests {
    use aegis_core::deadman::{
        aegis_deadman_check, aegis_deadman_heartbeat, aegis_deadman_set_timeout, DeadmanSwitch,
        MAX_TIMEOUT_SECS, MIN_TIMEOUT_SECS,
    };

    #[test]
    fn test_phase5_deadman_clamping_and_heartbeat() {
        DeadmanSwitch::init();
        assert_eq!(aegis_deadman_check(), 0);

        // Validation du bornage minimal (15 min = 900s)
        aegis_deadman_set_timeout(100);
        assert_eq!(MIN_TIMEOUT_SECS, 900);
        assert_eq!(aegis_deadman_check(), 0);

        // Validation du bornage maximal (4 h = 14400s)
        aegis_deadman_set_timeout(20000);
        assert_eq!(MAX_TIMEOUT_SECS, 14400);
        assert_eq!(aegis_deadman_check(), 0);

        // Heartbeat
        assert_eq!(aegis_deadman_heartbeat(), 0);
    }
}