#![no_main]
use libfuzzer_sys::fuzz_target;
use rekey_domain::connection::{MethodClass, RuleEffect, validate_path_pattern, validate_request_path};
use rekey_domain::action::FixedMethod;
use rekey_domain::ids::CredentialId;
fuzz_target!(|data: &[u8]| {
    let Ok(text)=std::str::from_utf8(data) else {return;};
    let (pattern,path)=text.split_once('\0').unwrap_or((text,text));
    if validate_request_path(path).is_err(){return;}
    if validate_path_pattern(pattern).is_err(){return;}
    let Ok(preset)=rekey_policy::presets::builtin_preset("github-pat") else {return;};
    let mut connection=preset.connection("fuzz".into(),CredentialId::from_random_bytes([1;16]));
    connection.rules[0].path=pattern.into();
    let mut tightened=connection.rules[0].clone();tightened.effect=RuleEffect::Deny;
    connection.caller_overrides.insert("fuzz".into(),vec![tightened]);
    for (method,class) in [(FixedMethod::Get,MethodClass::Read),(FixedMethod::Post,MethodClass::Write)] {
        let base=rekey_policy::connections::decide(&connection,method,class,path,"unknown").0;
        let tighter=rekey_policy::connections::decide(&connection,method,class,path,"fuzz").0;
        assert!(tighter>=base);
    }
});
