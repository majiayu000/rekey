//! rekeyd: the broker daemon and offline bootstrap binary. The `rekey` CLI
//! is a pure IPC client; everything that must touch the database, crypto, or
//! the network lives here. Secrets arrive only via hidden TTY prompt or an
//! explicit --password-stdin/--secret-stdin; never via argv or environment.

use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use rekey_broker::error::BrokerError;
use rekey_broker::runtime::{BrokerConfig, serve};
use rekey_vault::AuthorityError;
use rekey_vault::bootstrap::{RestoreProof, init_vault, restore_vault};
use rekey_vault::crypto::kdf::Argon2Params;
use rekey_vault::secret::SecretInput;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
enum RekeydError {
    #[error("{0}")]
    Usage(String),
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    #[error(transparent)]
    Broker(#[from] BrokerError),
}

impl RekeydError {
    fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => 2,
            Self::Authority(err) => authority_exit_code(err),
            Self::Broker(BrokerError::Authority(err)) => authority_exit_code(err),
            Self::Broker(BrokerError::Domain(_)) | Self::Broker(BrokerError::Frame(_)) => 2,
            Self::Broker(_) => 5,
        }
    }
}

fn authority_exit_code(err: &AuthorityError) -> i32 {
    match err {
        AuthorityError::InvalidUnlockCredential | AuthorityError::AuthenticationFailed => 3,
        AuthorityError::Domain(_) => 2,
        _ => 5,
    }
}

fn init_logging() {
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_current_span(false)
        .with_span_list(false)
        .init();
}

#[derive(Parser)]
#[command(
    name = "rekeyd",
    version,
    about = "rekey broker daemon and offline bootstrap"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new v2 vault in an empty state directory.
    Init {
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Read the password from stdin (first line) instead of the TTY.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Run the broker in the foreground (starts locked).
    Serve {
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Idle auto-lock, e.g. 15m, 1h. Range 1m..=120m.
        #[arg(long, default_value = "15m")]
        idle_lock: String,
        /// Separate directory that exposes only agent.sock to an isolated Agent.
        #[arg(long)]
        agent_runtime_dir: Option<PathBuf>,
        /// OS peer UID accepted on agent.sock (repeatable; defaults to Broker UID).
        #[arg(long = "agent-uid")]
        agent_uids: Vec<u32>,
        /// Shared GID for an isolated agent.sock (directory 0770, socket 0660).
        #[arg(long)]
        agent_gid: Option<u32>,
    },
    /// Restore a v2 backup into an empty state directory (offline).
    Restore {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Verify with the recovery key instead of the password.
        #[arg(long)]
        recovery: bool,
        #[arg(long)]
        password_stdin: bool,
        /// SHA-256 of the backup file from the backup receipt (64 hex chars).
        #[arg(long)]
        sha256: String,
    },
}

fn usage(message: impl Into<String>) -> RekeydError {
    RekeydError::Usage(message.into())
}

fn default_state_dir() -> Result<PathBuf, RekeydError> {
    std::env::home_dir()
        .map(|home| home.join(".rekey"))
        .ok_or_else(|| usage("cannot resolve home directory; pass --state-dir"))
}

fn resolve_state_dir(flag: Option<PathBuf>) -> Result<PathBuf, RekeydError> {
    flag.map_or_else(default_state_dir, Ok)
}

fn parse_duration(input: &str) -> Result<Duration, RekeydError> {
    let (value, unit) = input.split_at(input.len().saturating_sub(1));
    let n: u64 = value
        .parse()
        .map_err(|_| usage(format!("invalid duration: {input}")))?;
    match unit {
        "s" => Ok(Duration::from_secs(n)),
        "m" => Ok(Duration::from_secs(n * 60)),
        "h" => Ok(Duration::from_secs(n * 3600)),
        _ => Err(usage(format!("invalid duration unit in: {input}"))),
    }
}

fn read_stdin_secret_line() -> Result<SecretInput, RekeydError> {
    let mut buf = Zeroizing::new(String::new());
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|err| usage(format!("failed to read stdin: {err}")))?;
    let line = buf.lines().next().unwrap_or("").trim_end_matches('\r');
    if line.is_empty() {
        return Err(usage("empty secret on stdin"));
    }
    Ok(SecretInput::from_slice(line.as_bytes()))
}

fn prompt_secret(prompt: &str) -> Result<SecretInput, RekeydError> {
    let value = Zeroizing::new(
        rpassword::prompt_password(prompt)
            .map_err(|err| usage(format!("cannot read from tty: {err}")))?,
    );
    if value.is_empty() {
        return Err(usage("empty input"));
    }
    Ok(SecretInput::from_slice(value.as_bytes()))
}

fn cmd_init(state_dir: Option<PathBuf>, password_stdin: bool) -> Result<(), RekeydError> {
    let state_dir = resolve_state_dir(state_dir)?;
    let password = if password_stdin {
        read_stdin_secret_line()?
    } else {
        let first = prompt_secret("New vault password: ")?;
        let second = prompt_secret("Confirm password: ")?;
        if first.expose() != second.expose() {
            return Err(usage("passwords do not match"));
        }
        first
    };
    let outcome = init_vault(&state_dir, &password, Argon2Params::RFC9106_LOW_MEMORY)?;
    println!("vault initialized: {}", outcome.vault_id);
    println!("state directory: {}", state_dir.display());
    println!();
    println!("RECOVERY KEY (shown exactly once, store it offline):");
    println!("{}", *outcome.recovery_key_display);
    if !password_stdin {
        let tail: String = outcome
            .recovery_key_display
            .chars()
            .rev()
            .take(6)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        let confirmed = rpassword::prompt_password(
            "Type the last 6 characters of the recovery key to confirm you saved it: ",
        )
        .map_err(|err| usage(format!("cannot read from tty: {err}")))?;
        if confirmed.trim() != tail {
            rekey_vault::bootstrap::discard_vault_files(&state_dir);
            return Err(usage(
                "recovery key confirmation mismatch; the vault from this init was discarded",
            ));
        }
    }
    Ok(())
}

fn cmd_restore(
    input: PathBuf,
    state_dir: Option<PathBuf>,
    recovery: bool,
    password_stdin: bool,
    sha256: String,
) -> Result<(), RekeydError> {
    let state_dir = resolve_state_dir(state_dir)?;
    let secret = if password_stdin {
        read_stdin_secret_line()?
    } else if recovery {
        prompt_secret("Recovery key: ")?
    } else {
        prompt_secret("Vault password: ")?
    };
    let proof = if recovery {
        RestoreProof::RecoveryKey(secret)
    } else {
        RestoreProof::Password(secret)
    };
    let vault_id = restore_vault(&input, &state_dir, proof, &sha256)?;
    println!("restored vault {} into {}", vault_id, state_dir.display());
    Ok(())
}

fn cmd_serve(
    state_dir: Option<PathBuf>,
    idle_lock: &str,
    agent_runtime_dir: Option<PathBuf>,
    mut agent_uids: Vec<u32>,
    agent_gid: Option<u32>,
) -> Result<(), RekeydError> {
    let state_dir = resolve_state_dir(state_dir)?;
    let idle = parse_duration(idle_lock)?;
    if idle < Duration::from_secs(60) || idle > Duration::from_secs(120 * 60) {
        return Err(usage("idle lock must be between 1m and 120m"));
    }
    let broker_uid = unsafe { libc::geteuid() };
    if agent_uids.is_empty() {
        agent_uids.push(broker_uid);
    }
    agent_uids.sort_unstable();
    agent_uids.dedup();
    if agent_runtime_dir.is_none() && (agent_gid.is_some() || agent_uids != [broker_uid]) {
        return Err(usage(
            "custom Agent identity requires --agent-runtime-dir and --agent-gid",
        ));
    }
    if agent_uids.iter().any(|uid| *uid != broker_uid) && agent_gid.is_none() {
        return Err(usage("a different --agent-uid requires --agent-gid"));
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| usage(format!("cannot start runtime: {err}")))?;
    let config = BrokerConfig {
        state_dir,
        agent_runtime_dir,
        allowed_agent_uids: agent_uids,
        agent_socket_gid: agent_gid,
        idle_lock: idle,
        transport: None,
        unlock_backoff_base: Duration::from_secs(1),
        drain_timeout: rekey_broker::runtime::default_drain_timeout(),
    };
    tracing::info!(
        event = "runtime.starting",
        state = "locked",
        runtime_version = env!("CARGO_PKG_VERSION")
    );
    let result = runtime.block_on(serve(config)).map_err(RekeydError::from);
    if result.is_ok() {
        tracing::info!(event = "runtime.stopped", outcome = "success");
    }
    result
}

fn main() {
    init_logging();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Init {
            state_dir,
            password_stdin,
        } => cmd_init(state_dir, password_stdin),
        Command::Serve {
            state_dir,
            idle_lock,
            agent_runtime_dir,
            agent_uids,
            agent_gid,
        } => cmd_serve(
            state_dir,
            &idle_lock,
            agent_runtime_dir,
            agent_uids,
            agent_gid,
        ),
        Command::Restore {
            input,
            state_dir,
            recovery,
            password_stdin,
            sha256,
        } => cmd_restore(input, state_dir, recovery, password_stdin, sha256),
    };
    if let Err(err) = result {
        let exit_code = err.exit_code();
        tracing::error!(
            event = "rekeyd.command_failed",
            code = exit_code,
            message = %err
        );
        std::process::exit(exit_code);
    }
}
