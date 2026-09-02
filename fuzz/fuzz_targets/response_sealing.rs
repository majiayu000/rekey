#![no_main]

use libfuzzer_sys::fuzz_target;
use rekey_broker::executor::fuzz_response_sealing;

fuzz_target!(|data: &[u8]| {
    let first = data.len() / 3;
    let second = first.saturating_mul(2);
    let _ = fuzz_response_sealing(&data[..first], &data[first..second], &data[second..]);
});
