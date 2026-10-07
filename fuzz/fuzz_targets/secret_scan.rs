#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let split = data.len() / 2;
    if let Ok(positions) = rekey_vault::hygiene::matching_positions(&data[split..], &data[..split]) {
        assert!(positions.iter().all(|offset| *offset < data.len() - split));
    }
    if !data.is_empty() && data.len() <= 1024 {
        let positions = rekey_vault::hygiene::matching_positions(data, data).unwrap();
        assert!(positions.contains(&0));
    }
});
