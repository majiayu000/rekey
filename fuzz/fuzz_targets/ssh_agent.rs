#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {rekey_broker::fuzz_ssh_agent(data);});
