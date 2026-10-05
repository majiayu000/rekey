#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rekey_vault::hygiene::env::preview_bytes(data);
});
