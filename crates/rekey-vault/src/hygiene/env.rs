//! Dotenv ingestion is daemon-side. Previews never contain values, unsupported
//! syntax is retained, and rewrites use an exclusive 0600 backup and rename.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use rekey_domain::credential::{CredentialLabel, CredentialMetadata};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{SCAN_FILE_MAX_BYTES, invalid};
use crate::AuthorityError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvPreviewEntry {
    pub key: String,
    pub preset_hint: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvUnsupported {
    pub line: u64,
    pub key: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvPreview {
    pub entries: Vec<EnvPreviewEntry>,
    pub unsupported: Vec<EnvUnsupported>,
}
#[derive(Debug)]
pub struct EnvImportSelection {
    pub key: String,
    pub label: CredentialLabel,
}
#[derive(Debug)]
pub struct EnvImportRequest {
    pub path: PathBuf,
    pub selections: Vec<EnvImportSelection>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct EnvImportEntry {
    pub key: String,
    pub credential: CredentialMetadata,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct EnvImportReport {
    pub entries: Vec<EnvImportEntry>,
    pub unsupported: Vec<EnvUnsupported>,
}

/// The broker builds replacements only after a signed Connection exists.
#[derive(Debug)]
pub struct EnvReplacement {
    pub key: String,
    pub base_url_variable: String,
    pub base_url: String,
}

pub(crate) struct ParsedEntry {
    pub key: String,
    pub range: std::ops::Range<usize>,
    pub value: Zeroizing<Vec<u8>>,
}
pub(crate) struct ParsedEnv {
    pub raw: Zeroizing<Vec<u8>>,
    pub entries: Vec<ParsedEntry>,
    pub unsupported: Vec<EnvUnsupported>,
}

fn variable(key: &str) -> bool {
    let mut bytes = key.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

pub(crate) fn parse_env(raw: Zeroizing<Vec<u8>>) -> ParsedEnv {
    let mut entries = Vec::new();
    let mut unsupported = Vec::new();
    let mut offset = 0;
    let mut seen = BTreeSet::new();
    for (line_index, line) in raw.split_inclusive(|b| *b == b'\n').enumerate() {
        let range = offset..offset + line.len();
        offset = range.end;
        let Ok(text) = std::str::from_utf8(line) else {
            unsupported.push(EnvUnsupported {
                line: line_index as u64 + 1,
                key: None,
            });
            continue;
        };
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        let text = text.strip_prefix("export ").map_or(text, str::trim_start);
        let Some((key, rest)) = text.split_once('=') else {
            unsupported.push(EnvUnsupported {
                line: line_index as u64 + 1,
                key: None,
            });
            continue;
        };
        let key = key.trim();
        if !variable(key) {
            unsupported.push(EnvUnsupported {
                line: line_index as u64 + 1,
                key: None,
            });
            continue;
        }
        let value = parse_value(rest.trim());
        if value.as_ref().is_none_or(|bytes| bytes.is_empty()) || !seen.insert(key.to_owned()) {
            unsupported.push(EnvUnsupported {
                line: line_index as u64 + 1,
                key: Some(key.to_owned()),
            });
            continue;
        }
        entries.push(ParsedEntry {
            key: key.to_owned(),
            range,
            value: value.unwrap_or_default(),
        });
    }
    // Duplicate assignments have ambiguous dotenv semantics. Preserve every
    // occurrence rather than importing or rewriting one of them silently.
    let ambiguous: BTreeSet<_> = unsupported
        .iter()
        .filter_map(|item| item.key.as_ref())
        .cloned()
        .collect();
    entries.retain(|entry| !ambiguous.contains(&entry.key));
    ParsedEnv {
        raw,
        entries,
        unsupported,
    }
}

fn parse_value(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    if let Some(rest) = text.strip_prefix('\'') {
        let end = rest.find('\'')?;
        let suffix = rest[end + 1..].trim();
        if !suffix.is_empty() && !suffix.starts_with('#') {
            return None;
        }
        return Some(Zeroizing::new(rest.as_bytes()[..end].to_vec()));
    }
    if let Some(rest) = text.strip_prefix('"') {
        let mut bytes = Zeroizing::new(Vec::new());
        let mut iter = rest.bytes().enumerate();
        while let Some((index, byte)) = iter.next() {
            match byte {
                b'"' => {
                    let suffix = rest[index + 1..].trim();
                    return (suffix.is_empty() || suffix.starts_with('#')).then_some(bytes);
                }
                b'$' => return None,
                b'\\' => {
                    let (_, escaped) = iter.next()?;
                    bytes.push(match escaped {
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        b'"' | b'\\' => escaped,
                        _ => return None,
                    });
                }
                _ => bytes.push(byte),
            }
        }
        return None;
    }
    let bytes = text.as_bytes();
    let end = bytes
        .iter()
        .enumerate()
        .find_map(|(index, b)| {
            (*b == b'#' && (index == 0 || bytes[index - 1].is_ascii_whitespace())).then_some(index)
        })
        .unwrap_or(bytes.len());
    let value = text[..end].trim_end();
    if value.contains(['$', '\\']) {
        return None;
    }
    Some(Zeroizing::new(value.as_bytes().to_vec()))
}

fn preset_hint(entry: &ParsedEntry) -> Option<String> {
    let key = entry.key.as_str();
    let value = entry.value.as_slice();
    if key.starts_with("OPENAI_") || value.starts_with(b"sk-") {
        Some("openai".to_owned())
    } else if key.starts_with("GITHUB_")
        || key == "GH_TOKEN"
        || value.starts_with(b"ghp_")
        || value.starts_with(b"github_pat_")
    {
        Some("github".to_owned())
    } else if key.starts_with("AWS_") || value.starts_with(b"AKIA") {
        Some("aws".to_owned())
    } else {
        None
    }
}

/// Useful to the dotenv fuzz target; never returns secret-bearing values.
pub fn preview_bytes(bytes: &[u8]) -> EnvPreview {
    let parsed = parse_env(Zeroizing::new(bytes.to_vec()));
    preview(&parsed)
}
fn preview(parsed: &ParsedEnv) -> EnvPreview {
    EnvPreview {
        entries: parsed
            .entries
            .iter()
            .map(|entry| EnvPreviewEntry {
                key: entry.key.clone(),
                preset_hint: preset_hint(entry),
            })
            .collect(),
        unsupported: parsed.unsupported.clone(),
    }
}
pub fn preview_env(path: &Path) -> Result<EnvPreview, AuthorityError> {
    Ok(preview(&load_env(path)?))
}
pub(crate) fn load_env(path: &Path) -> Result<ParsedEnv, AuthorityError> {
    let (directory, name) = parent_directory(path)?;
    let mut file = open_at(&directory, &name, libc::O_RDONLY, 0)?;
    let metadata = file.metadata().map_err(AuthorityError::storage)?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(AuthorityError::InsecureStatePermissions);
    }
    let mut raw = Zeroizing::new(Vec::new());
    Read::by_ref(&mut file)
        .take(SCAN_FILE_MAX_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(AuthorityError::storage)?;
    if raw.len() > SCAN_FILE_MAX_BYTES {
        return Err(invalid("dotenv file exceeds 10 MiB"));
    }
    Ok(parse_env(raw))
}

fn cstring(bytes: &[u8]) -> Result<CString, AuthorityError> {
    CString::new(bytes).map_err(|_| invalid("invalid dotenv path"))
}
fn parent_directory(path: &Path) -> Result<(File, CString), AuthorityError> {
    let name = path
        .file_name()
        .ok_or_else(|| invalid("invalid dotenv path"))?;
    let mut directory =
        File::open(if path.is_absolute() { "/" } else { "." }).map_err(AuthorityError::storage)?;
    for component in path
        .parent()
        .ok_or_else(|| invalid("invalid dotenv path"))?
        .components()
    {
        let bytes = match component {
            Component::Normal(name) => name.as_bytes(),
            Component::ParentDir => b"..",
            Component::CurDir | Component::RootDir => continue,
            _ => return Err(invalid("invalid dotenv path")),
        };
        directory = open_at(
            &directory,
            &cstring(bytes)?,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
    }
    Ok((directory, cstring(name.as_bytes())?))
}
fn open_at(
    directory: &File,
    name: &CString,
    flags: i32,
    mode: u32,
) -> Result<File, AuthorityError> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(AuthorityError::storage(std::io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn private(file: &File) -> Result<(), AuthorityError> {
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(AuthorityError::storage(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// All replacement lines are supplied by the daemon after connection signing.
/// Unselected and unsupported lines survive byte-for-byte. Existing backups
/// are never overwritten, and symlinks are never followed.
pub fn rewrite_env(
    path: &Path,
    replacements: &[EnvReplacement],
) -> Result<PathBuf, AuthorityError> {
    if replacements.is_empty() {
        return Err(invalid("dotenv rewrite has no replacements"));
    }
    let parsed = load_env(path)?;
    let mut selected = BTreeMap::new();
    let mut generated = BTreeMap::new();
    for item in replacements {
        if !variable(&item.key)
            || !variable(&item.base_url_variable)
            || item.base_url.contains(['\n', '\r', '"', '$', '\\'])
            || !item.base_url.starts_with("http://127.0.0.1:")
        {
            return Err(invalid("invalid dotenv replacement"));
        }
        if !parsed.entries.iter().any(|entry| entry.key == item.key)
            || selected.insert(&item.key, item).is_some()
            || generated.insert(&item.base_url_variable, item).is_some()
        {
            return Err(invalid(
                "dotenv replacement key is unavailable or duplicated",
            ));
        }
    }
    if generated.keys().any(|key| selected.contains_key(key))
        || parsed.unsupported.iter().any(|item| {
            item.key
                .as_ref()
                .is_some_and(|key| generated.contains_key(key))
        })
    {
        return Err(invalid("dotenv base URL variable is ambiguous"));
    }
    let mut rewritten = Zeroizing::new(Vec::with_capacity(parsed.raw.len()));
    let mut written_urls = BTreeSet::new();
    let mut previous = 0;
    for entry in &parsed.entries {
        let replacement = if let Some(item) = selected.get(&entry.key) {
            format!("{}=rekey\n", item.key)
        } else if let Some(item) = generated.get(&entry.key) {
            written_urls.insert(&entry.key);
            format!("{}=\"{}\"\n", item.base_url_variable, item.base_url)
        } else {
            continue;
        };
        rewritten.extend_from_slice(&parsed.raw[previous..entry.range.start]);
        rewritten.extend_from_slice(replacement.as_bytes());
        previous = entry.range.end;
    }
    rewritten.extend_from_slice(&parsed.raw[previous..]);
    if !rewritten.ends_with(b"\n") {
        rewritten.push(b'\n');
    }
    for item in replacements {
        if written_urls.contains(&item.base_url_variable) {
            continue;
        }
        rewritten.extend_from_slice(
            format!("{}=\"{}\"\n", item.base_url_variable, item.base_url).as_bytes(),
        );
    }
    let (directory, name) = parent_directory(path)?;
    // Compare the opened file immediately before mutation. A concurrent edit
    // aborts; no changed project file is overwritten.
    let mut current = open_at(&directory, &name, libc::O_RDONLY, 0)?;
    let original_metadata = current.metadata().map_err(AuthorityError::storage)?;
    let mut current_bytes = Zeroizing::new(Vec::new());
    Read::by_ref(&mut current)
        .take(SCAN_FILE_MAX_BYTES as u64 + 1)
        .read_to_end(&mut current_bytes)
        .map_err(AuthorityError::storage)?;
    if *current_bytes != *parsed.raw {
        return Err(invalid("dotenv changed during import"));
    }
    let backup_name = cstring(&[name.as_bytes(), b".rekey-backup"].concat())?;
    let mut backup = open_at(
        &directory,
        &backup_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    private(&backup)?;
    backup
        .write_all(&parsed.raw)
        .map_err(AuthorityError::storage)?;
    backup.sync_all().map_err(AuthorityError::storage)?;
    directory.sync_all().map_err(AuthorityError::storage)?;
    let temporary_name = cstring(
        &[
            name.as_bytes(),
            b".rekey-tmp-",
            data_encoding::HEXLOWER
                .encode(&crate::crypto::random_array::<16>()?)
                .as_bytes(),
        ]
        .concat(),
    )?;
    let mut temporary = open_at(
        &directory,
        &temporary_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    private(&temporary)?;
    let mutation = (|| {
        temporary
            .write_all(&rewritten)
            .map_err(AuthorityError::storage)?;
        temporary.sync_all().map_err(AuthorityError::storage)?;
        let latest = open_at(&directory, &name, libc::O_RDONLY, 0)?
            .metadata()
            .map_err(AuthorityError::storage)?;
        if latest.dev() != original_metadata.dev()
            || latest.ino() != original_metadata.ino()
            || latest.mtime() != original_metadata.mtime()
            || latest.mtime_nsec() != original_metadata.mtime_nsec()
        {
            return Err(invalid("dotenv changed during import"));
        }
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary_name.as_ptr(),
                directory.as_raw_fd(),
                name.as_ptr(),
            )
        } != 0
        {
            return Err(AuthorityError::storage(std::io::Error::last_os_error()));
        }
        directory.sync_all().map_err(AuthorityError::storage)
    })();
    if mutation.is_err() {
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), temporary_name.as_ptr(), 0);
        }
    }
    mutation?;
    Ok(path.with_file_name(std::ffi::OsStr::from_bytes(backup_name.as_bytes())))
}
