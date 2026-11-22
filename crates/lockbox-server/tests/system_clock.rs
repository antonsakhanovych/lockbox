use std::time::{SystemTime, UNIX_EPOCH};

use lockbox_server::adapters::driven::SystemClock;
use lockbox_server::core::ports::driven::Clock;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn the_system_clock_reports_unix_seconds() {
    let before = unix_now();
    let now = SystemClock.now();
    let after = unix_now();
    assert!(before <= now && now <= after);
}

#[test]
fn the_system_clock_never_goes_backwards_between_reads() {
    let first = SystemClock.now();
    let second = SystemClock.now();
    assert!(second >= first);
}
