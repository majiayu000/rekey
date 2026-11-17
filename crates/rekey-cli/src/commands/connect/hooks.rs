//! The Git pre-commit scan shared by `rekey connect --with-hooks` and
//! `rekey hooks`. A shell hook gets the marked block right after its shebang,
//! so the scan runs first even when the hook ends with `exec` or `exit`, and
//! `$0` stays the same. Any other hook (another interpreter, a binary or a
//! hook disabled by its mode) moves unchanged to `pre-commit.rekey-chained`,
//! which a managed sh wrapper runs after the scan with the same arguments and
//! standard input.
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::Subcommand;

use super::edit::{Edit, marked, review};
use super::{LOCAL_PATH_WARNING, Vault, invalid, io_error, project_dir};
use crate::client::CliError;

const HOOK: &str = "pre-commit";
const CHAINED: &str = "pre-commit.rekey-chained";
const BEGIN: &str = "# rekey:begin";
const END: &str = "# rekey:end";
/// The managed wrapper around its marked block.
const WRAPPER: [&str; 2] = [
    "#!/bin/sh\n",
    "# Rekey-managed hook. A pre-commit hook that existed before Rekey runs next,\n\
     # from pre-commit.rekey-chained, with the same arguments and input.\n\
     case $0 in */*) chained=\"${0%/*}/pre-commit.rekey-chained\" ;; *) chained=./pre-commit.rekey-chained ;; esac\n\
     if [ -x \"$chained\" ]; then exec \"$chained\" \"$@\"; fi\n",
];
/// Interpreters that run the inserted block as written; other hooks are chained.
const SHELLS: [&str; 7] = ["sh", "bash", "dash", "ash", "ksh", "mksh", "zsh"];

#[derive(Subcommand)]
pub enum HooksCommand {
    /// Install the pre-commit secret scan; an existing hook is chained, not replaced.
    Install {
        #[arg(long)]
        print: bool,
        #[arg(long)]
        project: Option<PathBuf>,
    },
    /// Remove the Rekey scan and restore the hook it chained.
    Uninstall {
        #[arg(long)]
        print: bool,
        #[arg(long)]
        project: Option<PathBuf>,
    },
}

pub fn hooks(command: HooksCommand, state_dir: &Path) -> Result<(), CliError> {
    match command {
        HooksCommand::Install { print, project } => review(
            install(&project_dir(project)?, &Vault::resolve(state_dir)?)?,
            print,
            "Install the Rekey pre-commit hook?",
            "Rekey pre-commit hook installed.",
        ),
        HooksCommand::Uninstall { print, project } => match uninstall(&project_dir(project)?)? {
            Some(edit) => review(
                vec![edit],
                print,
                "Remove the Rekey pre-commit hook?",
                "Rekey pre-commit hook removed.",
            ),
            None => writeln!(
                io::stdout(),
                "No Rekey pre-commit hook is installed; no files changed."
            )
            .map_err(|e| io_error("cannot write result", e)),
        },
    }
}

/// The hook and its chained sibling in Git's hooks directory (core.hooksPath
/// included), and whether that directory lies outside the Git directory,
/// where it could be committed.
fn locate(project: &Path) -> Result<(Edit, Edit, bool), CliError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(project)
        .args(["rev-parse", "--path-format=absolute"])
        .args(["--git-path", "hooks", "--git-common-dir"])
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .stdin(Stdio::null())
        .output()
        .map_err(|_| invalid("cannot locate Git hooks directory"))?;
    if !output.status.success() {
        return Err(invalid("the pre-commit hook requires a Git repository"));
    }
    let text =
        std::str::from_utf8(&output.stdout).map_err(|_| invalid("Git hooks path must be UTF-8"))?;
    let mut lines = text.lines();
    let (Some(hooks), Some(git_dir), None) = (lines.next(), lines.next(), lines.next()) else {
        return Err(invalid("cannot locate Git hooks directory"));
    };
    let hooks = std::path::absolute(hooks)
        .map_err(|e| io_error("cannot resolve Git hooks directory", e))?;
    let committable = !hooks.starts_with(git_dir);
    let load = |filename| {
        if hooks.is_dir() {
            Edit::load(hooks.clone(), None, filename)
        } else if hooks.file_name().and_then(|s| s.to_str()) == Some("hooks") {
            let parent = hooks
                .parent()
                .ok_or_else(|| invalid("Git hooks directory has no parent"))?;
            Edit::load(parent.to_owned(), Some("hooks"), filename)
        } else {
            Err(invalid("custom Git hooks directories must already exist"))
        }
    };
    Ok((load(HOOK)?, load(CHAINED)?, committable))
}

/// The edits that install the scan: the hook, preceded by the chained copy
/// of the existing hook when that hook needs the wrapper.
pub(super) fn install(project: &Path, vault: &Vault) -> Result<Vec<Edit>, CliError> {
    let (mut hook, mut chained, committable) = locate(project)?;
    // The hook's own input stays for the hook; the scan never reads it.
    let block = format!(
        "{BEGIN}\n{} scan --staged </dev/null || exit $?\n{END}\n",
        vault.rekey
    );
    let wrapper = format!("{}{block}{}", WRAPPER[0], WRAPPER[1]);
    if vault.custom.is_some() && committable {
        hook.warning = Some(LOCAL_PATH_WARNING);
    }
    hook.mode = Some(0o700);
    let (own, managed, mode) = match &hook.original {
        None => (Vec::new(), false, 0o700),
        Some(old) => {
            let (own, managed) = unmanaged(&old.bytes)?;
            (own, managed, old.mode)
        }
    };
    if blank(&own) {
        // No hook of the user's own: Rekey owns the whole file.
        if chained.original.is_some() {
            return Err(invalid(
                "pre-commit.rekey-chained exists without a Rekey-managed pre-commit hook; restore or remove it first",
            ));
        }
        hook.before = if hook.original.is_none() {
            "<no pre-commit hook>"
        } else {
            "<existing hook without commands>"
        }
        .into();
        hook.updated = wrapper.clone().into_bytes();
        hook.after = wrapper;
        return Ok(vec![hook]);
    }
    if let Ok(text) = std::str::from_utf8(&own)
        && shell(text)
        && (managed || mode & 0o100 != 0)
    {
        hook.mode = Some(mode | 0o100);
        hook.updated = match text.split_once('\n') {
            Some((first, rest)) => format!("{first}\n{block}{rest}"),
            None => format!("{text}\n{block}"),
        }
        .into_bytes();
        hook.before = "<existing hook; the Rekey block runs right after its first line>".into();
        hook.after = block;
        return Ok(vec![hook]);
    }
    let mut edits = Vec::new();
    match &chained.original {
        // Left by an interrupted install: exactly the hook being chained.
        Some(old) if old.bytes == own && old.mode == mode => {}
        Some(_) => {
            return Err(invalid(
                "pre-commit.rekey-chained already exists; move it away before installing the Rekey hook",
            ));
        }
        None => {
            chained.mode = Some(mode);
            chained.updated = own;
            chained.before = "<none>".into();
            chained.after = "<the existing pre-commit hook, unchanged>".into();
            edits.push(chained);
        }
    }
    hook.before = "<existing hook, kept as pre-commit.rekey-chained>".into();
    hook.updated = wrapper.clone().into_bytes();
    hook.after = wrapper;
    edits.push(hook);
    Ok(edits)
}

/// The single edit that removes the scan, or None when no Rekey hook exists.
fn uninstall(project: &Path) -> Result<Option<Edit>, CliError> {
    let (mut hook, chained, _) = locate(project)?;
    let Some(old) = &hook.original else {
        return Ok(None);
    };
    let (own, managed) = unmanaged(&old.bytes)?;
    if !managed {
        return Ok(None);
    }
    let mode = old.mode;
    hook.before = "<Rekey-managed hook>".into();
    let wrapper = own == format!("{}{}", WRAPPER[0], WRAPPER[1]).as_bytes();
    match chained.original {
        Some(original) if wrapper => {
            hook.restore = Some((CHAINED, original));
            hook.after = "<pre-commit.rekey-chained moved back to pre-commit>".into();
        }
        _ if wrapper || blank(&own) => {
            hook.remove = true;
            hook.after = "<removed>".into();
        }
        _ => {
            hook.before = "<existing hook with the Rekey block>".into();
            hook.mode = Some(mode);
            hook.updated = own;
            hook.after = "<existing hook without the Rekey block>".into();
        }
    }
    Ok(Some(hook))
}

/// The hook without Rekey's marked block, and whether the block was there.
fn unmanaged(bytes: &[u8]) -> Result<(Vec<u8>, bool), CliError> {
    let found = [BEGIN, END]
        .iter()
        .any(|marker| bytes.windows(marker.len()).any(|w| w == marker.as_bytes()));
    Ok(if found {
        (marked(bytes, "", BEGIN, END)?, true)
    } else {
        (bytes.to_vec(), false)
    })
}

/// Nothing to keep: empty, or the bare shebang older Rekey versions wrote.
fn blank(own: &[u8]) -> bool {
    matches!(own.trim_ascii(), b"" | b"#!/bin/sh")
}

/// Whether the first line runs a POSIX-family shell, directly or through env.
fn shell(text: &str) -> bool {
    let base = |path: &str| path.rsplit('/').next().unwrap_or(path).to_owned();
    let Some(line) = text.lines().next().and_then(|line| line.strip_prefix("#!")) else {
        return false;
    };
    let mut words = line.split_ascii_whitespace();
    let mut program = words.next().map(base);
    if program.as_deref() == Some("env") {
        program = words
            .find(|word| !word.starts_with('-') && !word.contains('='))
            .map(base);
    }
    program.is_some_and(|program| SHELLS.contains(&program.as_str()))
}

#[cfg(test)]
mod tests {
    use super::shell;
    #[test]
    fn only_posix_family_shebangs_take_the_inserted_block() {
        for line in [
            "#!/bin/sh",
            "#! /bin/bash -e",
            "#!/usr/bin/env bash",
            "#!/usr/bin/env -S zsh -f",
            "#!/usr/bin/env LANG=C dash",
        ] {
            assert!(shell(&format!("{line}\nexit 0\n")), "{line}");
        }
        for line in [
            "#!/usr/bin/env python3",
            "#!/usr/bin/env fish",
            "#!/bin/csh",
            "#!/usr/bin/env node",
            "exit 0",
            "",
        ] {
            assert!(!shell(&format!("{line}\nexit 0\n")), "{line}");
        }
    }
}
