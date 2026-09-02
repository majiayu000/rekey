#![no_main]

use libfuzzer_sys::fuzz_target;
use rekey_domain::action::{ActionName, ExactPath, FixedHttpAction, HeaderName, HttpsOrigin};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Ok(value) = ActionName::new(&text) {
        let reparsed = ActionName::new(value.as_str()).expect("normalized action name reparses");
        assert_eq!(reparsed.as_str(), value.as_str());
    }
    if let Ok(value) = HttpsOrigin::parse(&text) {
        let reparsed = HttpsOrigin::parse(value.as_str()).expect("normalized origin reparses");
        assert_eq!(reparsed.as_str(), value.as_str());
    }
    if let Ok(value) = ExactPath::parse(&text) {
        let reparsed = ExactPath::parse(value.as_str()).expect("normalized path reparses");
        assert_eq!(reparsed.as_str(), value.as_str());
    }
    if let Ok(value) = HeaderName::new(&text) {
        let reparsed = HeaderName::new(value.as_str()).expect("normalized header reparses");
        assert_eq!(reparsed.as_str(), value.as_str());
    }
    if let Ok(action) = serde_json::from_slice::<FixedHttpAction>(data) {
        let _ = action.validate();
    }
});
