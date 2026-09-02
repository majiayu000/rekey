#![no_main]

use libfuzzer_sys::fuzz_target;
use rekey_domain::Timestamp;
use rekey_policy::parse_and_validate_snapshot;

fuzz_target!(|data: &[u8]| {
    let _ = parse_and_validate_snapshot(data, Timestamp::from_unix_ms(0));
});
