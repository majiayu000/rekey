//! macOS signing identity of an ancestor process, looked up by PID. PID reuse
//! can mislabel; that is acceptable only because labels never authorize.
use std::collections::BTreeMap;
use std::ffi::{c_char, c_void};
use std::ptr;
use std::sync::Mutex;

use super::known;

type CFRef = *const c_void;
const UTF8: u32 = 0x0800_0100;
const SINT32: isize = 3;
const SIGNING_INFORMATION: u32 = 1 << 1;
const CACHE_LIMIT: usize = 1024;
/// Platform binaries (shells, terminals, system tools) are never known Agents.
const SYSTEM: [&str; 6] = [
    "/System/",
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/libexec/",
];

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: CFRef);
    fn CFGetTypeID(value: CFRef) -> usize;
    fn CFStringGetTypeID() -> usize;
    fn CFStringCreateWithBytes(
        allocator: CFRef,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        external: u8,
    ) -> CFRef;
    fn CFStringGetLength(value: CFRef) -> isize;
    fn CFStringGetMaximumSizeForEncoding(length: isize, encoding: u32) -> isize;
    fn CFStringGetCString(value: CFRef, buffer: *mut c_char, size: isize, encoding: u32) -> u8;
    fn CFNumberCreate(allocator: CFRef, kind: isize, value: *const c_void) -> CFRef;
    fn CFDictionaryCreate(
        allocator: CFRef,
        keys: *const CFRef,
        values: *const CFRef,
        count: isize,
        key_callbacks: CFRef,
        value_callbacks: CFRef,
    ) -> CFRef;
    fn CFDictionaryGetValue(dictionary: CFRef, key: CFRef) -> CFRef;
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecGuestAttributePid: CFRef;
    static kSecCodeInfoIdentifier: CFRef;
    static kSecCodeInfoTeamIdentifier: CFRef;
    fn SecCodeCopyGuestWithAttributes(
        host: CFRef,
        attributes: CFRef,
        flags: u32,
        code: *mut CFRef,
    ) -> i32;
    fn SecCodeCopySigningInformation(code: CFRef, flags: u32, info: *mut CFRef) -> i32;
    fn SecRequirementCreateWithString(text: CFRef, flags: u32, requirement: *mut CFRef) -> i32;
    fn SecCodeCheckValidity(code: CFRef, flags: u32, requirement: CFRef) -> i32;
}

// Every Create/Copy result is owned exactly once, including early returns.
struct Owned(CFRef);
impl Owned {
    fn new(value: CFRef) -> Option<Self> {
        (!value.is_null()).then_some(Self(value))
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0) };
    }
}

static CACHE: Mutex<BTreeMap<(i32, String), Option<&'static str>>> = Mutex::new(BTreeMap::new());

/// The known-Agent label of a validly signed process, cached per PID and
/// real path. Failed or unsigned lookups are simply not a match.
pub(super) fn label(pid: i32, path: &str) -> Option<&'static str> {
    if SYSTEM.iter().any(|prefix| path.starts_with(prefix)) {
        return None;
    }
    let key = (pid, path.to_owned());
    if let Some(hit) = CACHE.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
        return *hit;
    }
    let found = lookup(pid);
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if cache.len() >= CACHE_LIMIT {
        cache.clear();
    }
    cache.insert(key, found);
    found
}

fn lookup(pid: i32) -> Option<&'static str> {
    let code = guest(pid)?;
    let (identifier, team) = identity(&code)?;
    let agent = known::by_signature(&team?, &identifier?)?;
    // A claimed team means nothing until the code validates against an
    // Apple-issued certificate for exactly that team.
    let requirement = format!(
        "anchor apple generic and certificate leaf[subject.OU] = \"{}\"",
        agent.team
    );
    let text = Owned::new(unsafe {
        CFStringCreateWithBytes(
            ptr::null(),
            requirement.as_ptr(),
            requirement.len() as isize,
            UTF8,
            0,
        )
    })?;
    let mut raw = ptr::null();
    if unsafe { SecRequirementCreateWithString(text.0, 0, &mut raw) } != 0 {
        return None;
    }
    let requirement = Owned::new(raw)?;
    (unsafe { SecCodeCheckValidity(code.0, 0, requirement.0) } == 0).then_some(agent.label)
}

fn guest(pid: i32) -> Option<Owned> {
    let number =
        Owned::new(unsafe { CFNumberCreate(ptr::null(), SINT32, (&pid as *const i32).cast()) })?;
    let key = unsafe { kSecGuestAttributePid };
    // Null callbacks borrow the static key and the number; both outlive it.
    let attributes = Owned::new(unsafe {
        CFDictionaryCreate(ptr::null(), &key, &number.0, 1, ptr::null(), ptr::null())
    })?;
    let mut code = ptr::null();
    if unsafe { SecCodeCopyGuestWithAttributes(ptr::null(), attributes.0, 0, &mut code) } != 0 {
        return None;
    }
    Owned::new(code)
}

/// Claimed (identifier, team); unsigned and ad-hoc code has no team.
fn identity(code: &Owned) -> Option<(Option<String>, Option<String>)> {
    let mut info = ptr::null();
    if unsafe { SecCodeCopySigningInformation(code.0, SIGNING_INFORMATION, &mut info) } != 0 {
        return None;
    }
    let info = Owned::new(info)?;
    let field = |key: CFRef| string(unsafe { CFDictionaryGetValue(info.0, key) });
    Some((
        field(unsafe { kSecCodeInfoIdentifier }),
        field(unsafe { kSecCodeInfoTeamIdentifier }),
    ))
}

fn string(value: CFRef) -> Option<String> {
    if value.is_null() || unsafe { CFGetTypeID(value) != CFStringGetTypeID() } {
        return None;
    }
    let capacity = unsafe { CFStringGetMaximumSizeForEncoding(CFStringGetLength(value), UTF8) }
        .checked_add(1)
        .filter(|size| *size > 0)?;
    let mut buffer = vec![0_u8; capacity as usize];
    if unsafe { CFStringGetCString(value, buffer.as_mut_ptr().cast(), capacity, UTF8) } == 0 {
        return None;
    }
    let text = std::ffi::CStr::from_bytes_until_nul(&buffer)
        .ok()?
        .to_str()
        .ok()?;
    (!text.is_empty()).then(|| text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ad_hoc_signed_process_has_no_team_and_no_agent_label() {
        let pid = std::process::id() as i32;
        let code = guest(pid).expect("own SecCode");
        let (_, team) = identity(&code).expect("own signing information");
        // Cargo test binaries are unsigned or linker-signed ad hoc.
        assert_eq!(team, None);
        let path = std::env::current_exe().unwrap();
        assert_eq!(label(pid, path.to_str().unwrap()), None);
        assert_eq!(lookup(pid), None);
        // System locations are skipped without a Security framework query.
        assert_eq!(label(pid, "/bin/zsh"), None);
    }
}
