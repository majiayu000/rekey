//! Public macOS dynamic code validation, before any IPC bytes are sent.
//! LOCAL_PEERTOKEN is a point-in-time identity lookup, not a guarantee against
//! socket descriptor aliasing or PID reuse before the kernel obtains the token.

use std::ffi::{c_char, c_void};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::ptr;

use super::{CliError, PeerSecurity};

type CFRef = *const c_void;
const UTF8: u32 = 0x0800_0100;
const SIGNING_INFORMATION: u32 = 1 << 1;
const SIGNATURE_ADHOC: i32 = 0x0002;
const UNSIGNED: i32 = -67062;
const TRUSTED_APPLE: &str = "anchor apple generic and anchor trusted";

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: CFRef);
    fn CFGetTypeID(value: CFRef) -> usize;
    fn CFStringGetTypeID() -> usize;
    fn CFNumberGetTypeID() -> usize;
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
    fn CFNumberGetValue(value: CFRef, kind: isize, output: *mut c_void) -> u8;
    fn CFDataCreate(allocator: CFRef, bytes: *const u8, length: isize) -> CFRef;
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
    static kSecCodeInfoIdentifier: CFRef;
    static kSecCodeInfoFlags: CFRef;
    static kSecCodeInfoTeamIdentifier: CFRef;
    static kSecGuestAttributeAudit: CFRef;
    fn SecCodeCopySelf(flags: u32, code: *mut CFRef) -> i32;
    fn SecCodeCopySigningInformation(code: CFRef, flags: u32, info: *mut CFRef) -> i32;
    fn SecRequirementCreateWithString(text: CFRef, flags: u32, requirement: *mut CFRef) -> i32;
    fn SecCodeCopyGuestWithAttributes(
        host: CFRef,
        attributes: CFRef,
        flags: u32,
        code: *mut CFRef,
    ) -> i32;
    fn SecCodeCheckValidity(code: CFRef, flags: u32, requirement: CFRef) -> i32;
}

// Every Copy/Create result is owned exactly once, including early-return paths.
struct OwnedCF(CFRef);
impl OwnedCF {
    fn new(value: CFRef, stage: &str) -> Result<Self, CliError> {
        if value.is_null() {
            Err(failure(stage, "missing Security framework result"))
        } else {
            Ok(Self(value))
        }
    }
}
impl Drop for OwnedCF {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0) };
    }
}

fn failure(stage: &str, detail: impl std::fmt::Display) -> CliError {
    CliError::local(
        "IPC_UNAVAILABLE",
        format!(
            "broker identity verification failed ({stage}: {detail}); possible forged Rekey service"
        ),
    )
}

fn check(status: i32, stage: &str) -> Result<(), CliError> {
    if status == 0 {
        Ok(())
    } else {
        Err(failure(stage, format_args!("OSStatus {status}")))
    }
}

fn requirement(text: &str) -> Result<OwnedCF, CliError> {
    let length =
        isize::try_from(text.len()).map_err(|_| failure("requirement", "text too long"))?;
    let string = OwnedCF::new(
        unsafe { CFStringCreateWithBytes(ptr::null(), text.as_ptr(), length, UTF8, 0) },
        "CFStringCreateWithBytes",
    )?;
    let mut result = ptr::null();
    check(
        unsafe { SecRequirementCreateWithString(string.0, 0, &mut result) },
        "SecRequirementCreateWithString",
    )?;
    OwnedCF::new(result, "SecRequirementCreateWithString")
}

fn string_value(value: CFRef) -> Result<String, CliError> {
    if value.is_null() || unsafe { CFGetTypeID(value) != CFStringGetTypeID() } {
        return Err(failure(
            "self TeamID",
            "missing or invalid signing identity",
        ));
    }
    let capacity = unsafe { CFStringGetMaximumSizeForEncoding(CFStringGetLength(value), UTF8) }
        .checked_add(1)
        .filter(|length| *length > 0)
        .ok_or_else(|| failure("self TeamID", "invalid string size"))?;
    let mut buffer = vec![0_u8; capacity as usize];
    if unsafe { CFStringGetCString(value, buffer.as_mut_ptr().cast(), capacity, UTF8) } == 0 {
        return Err(failure("self TeamID", "cannot decode signing identity"));
    }
    let value = std::ffi::CStr::from_bytes_until_nul(&buffer)
        .map_err(|_| failure("self TeamID", "unterminated signing identity"))?
        .to_str()
        .map_err(|_| failure("self TeamID", "invalid UTF-8 signing identity"))?;
    if value.is_empty() {
        return Err(failure("self TeamID", "empty signing identity"));
    }
    Ok(value.to_owned())
}

// None is an explicitly unsigned or valid ad-hoc development build. A broken
// certificate signature, missing TeamID, or API failure never enables dev mode.
pub(super) fn own_team() -> Result<Option<&'static str>, CliError> {
    // The prompt and connection share one self lookup; each peer is checked anew.
    static TEAM: std::sync::OnceLock<Result<Option<String>, CliError>> = std::sync::OnceLock::new();
    match TEAM.get_or_init(read_own_team) {
        Ok(team) => Ok(team.as_deref()),
        Err(error) => Err(CliError::local(&error.code, &error.message)),
    }
}

fn read_own_team() -> Result<Option<String>, CliError> {
    let mut code = ptr::null();
    check(unsafe { SecCodeCopySelf(0, &mut code) }, "SecCodeCopySelf")?;
    let code = OwnedCF::new(code, "SecCodeCopySelf")?;
    let validity = unsafe { SecCodeCheckValidity(code.0, 0, ptr::null()) };
    if validity != 0 && validity != UNSIGNED {
        return Err(failure(
            "self SecCodeCheckValidity",
            format_args!("OSStatus {validity}"),
        ));
    }
    let mut info = ptr::null();
    check(
        unsafe { SecCodeCopySigningInformation(code.0, SIGNING_INFORMATION, &mut info) },
        "self SecCodeCopySigningInformation",
    )?;
    let info = OwnedCF::new(info, "self SecCodeCopySigningInformation")?;
    let identifier = unsafe { CFDictionaryGetValue(info.0, kSecCodeInfoIdentifier) };
    if validity == UNSIGNED && identifier.is_null() {
        return Ok(None);
    }
    check(validity, "self SecCodeCheckValidity")?;
    if identifier.is_null() {
        return Err(failure("self signature", "missing code identifier"));
    }
    let flags = unsafe { CFDictionaryGetValue(info.0, kSecCodeInfoFlags) };
    let mut signature_flags: i32 = 0;
    if flags.is_null()
        || unsafe { CFGetTypeID(flags) != CFNumberGetTypeID() }
        // kCFNumberSInt32Type = 3; do not reinterpret an untyped CFNumber.
        || unsafe { CFNumberGetValue(flags, 3, (&mut signature_flags as *mut i32).cast()) } == 0
    {
        return Err(failure(
            "self signature",
            "missing or invalid signature flags",
        ));
    }
    if signature_flags & SIGNATURE_ADHOC != 0 {
        return Ok(None);
    }
    let trusted = requirement(TRUSTED_APPLE)?;
    check(
        unsafe { SecCodeCheckValidity(code.0, 0, trusted.0) },
        "self trusted signature",
    )?;
    string_value(unsafe { CFDictionaryGetValue(info.0, kSecCodeInfoTeamIdentifier) }).map(Some)
}

pub(super) fn verify(stream: &UnixStream) -> Result<PeerSecurity, CliError> {
    let Some(team) = own_team()? else {
        return Ok(PeerSecurity::L1Dev);
    };
    // Public mach/message.h defines audit_token_t as eight unsigned 32-bit words.
    // Treat the token as opaque; never extract a PID or fall back to LOCAL_PEERPID.
    let mut token = [0_u32; 8];
    let mut length = std::mem::size_of_val(&token) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(failure("LOCAL_PEERTOKEN", std::io::Error::last_os_error()));
    }
    if length as usize != std::mem::size_of_val(&token) {
        return Err(failure("LOCAL_PEERTOKEN", "unexpected audit token size"));
    }
    let data = OwnedCF::new(
        unsafe { CFDataCreate(ptr::null(), token.as_ptr().cast(), length as isize) },
        "CFDataCreate",
    )?;
    let key = unsafe { kSecGuestAttributeAudit };
    // Null callbacks borrow these pointers. Both key (static) and data outlive
    // the dictionary and its only use below; no CF callback ABI is needed.
    let attributes = OwnedCF::new(
        unsafe { CFDictionaryCreate(ptr::null(), &key, &data.0, 1, ptr::null(), ptr::null()) },
        "CFDictionaryCreate",
    )?;
    let mut peer = ptr::null();
    check(
        unsafe { SecCodeCopyGuestWithAttributes(ptr::null(), attributes.0, 0, &mut peer) },
        "peer SecCodeCopyGuestWithAttributes",
    )?;
    let peer = OwnedCF::new(peer, "peer SecCodeCopyGuestWithAttributes")?;
    let quoted_team = team.replace('\\', "\\\\").replace('"', "\\\"");
    let expected = requirement(&format!(
        "{TRUSTED_APPLE} and certificate leaf[subject.OU] = \"{quoted_team}\" and identifier \"com.rekey.rekeyd\""
    ))?;
    check(
        unsafe { SecCodeCheckValidity(peer.0, 0, expected.0) },
        "peer SecCodeCheckValidity",
    )?;
    Ok(PeerSecurity::VerifiedSignature)
}
