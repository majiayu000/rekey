#![no_main]

use libfuzzer_sys::fuzz_target;
use rekey_domain::action::{ActionName, ExactPath, FixedHttpAction, HeaderName, HttpsOrigin};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = ActionName::new(&text);
    let _ = HttpsOrigin::parse(&text);
    let _ = ExactPath::parse(&text);
    let _ = HeaderName::new(&text);
    let _ = serde_json::from_slice::<FixedHttpAction>(data);
});
