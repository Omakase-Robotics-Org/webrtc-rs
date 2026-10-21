//! The process-wide backoff cap, through the public API. Its own test binary
//! (its own process), so changing the cap cannot race the crate's unit tests.

use std::time::Duration;

use webrtc_sctp::{max_timer_backoff, set_max_timer_backoff};

#[test]
fn set_max_timer_backoff_round_trips_and_restores_the_default() {
    assert_eq!(max_timer_backoff(), Duration::from_secs(60));
    set_max_timer_backoff(Duration::from_secs(1));
    assert_eq!(max_timer_backoff(), Duration::from_secs(1));
    set_max_timer_backoff(Duration::from_millis(1500));
    assert_eq!(max_timer_backoff(), Duration::from_millis(1500));
    set_max_timer_backoff(Duration::from_secs(60));
    assert_eq!(max_timer_backoff(), Duration::from_secs(60));
}
