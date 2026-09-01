//! rekey: IPC-only admin/agent CLI. Offline bootstrap (init/restore) and the
//! broker itself live in `rekeyd`; this binary delegates those subcommands to
//! it so the CLI process never holds database or crypto capability.

mod client;
mod commands;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "rekey",
    version,
    about = "credential authority CLI (IPC client)"
)]
struct Cli {
    /// State directory (default ~/.rekey).
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    /// Agent socket path for an isolated data-plane endpoint.
    #[arg(long, global = true)]
    agent_socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new vault (delegates to rekeyd).
    Init {
        #[arg(long)]
        password_stdin: bool,
    },
    /// Run the broker in the foreground (delegates to rekeyd).
    Serve {
        #[arg(long, default_value = "15m")]
        idle_lock: String,
    },
    /// Restore a backup into an empty state directory (delegates to rekeyd).
    Restore {
        #[arg(long)]
        input: PathBuf,
        /// Verify the backup with the recovery key; does not reset the password.
        #[arg(long)]
        recovery: bool,
        #[arg(long)]
        password_stdin: bool,
        /// SHA-256 of the backup file from the backup receipt (64 hex chars).
        #[arg(long)]
        sha256: String,
    },
    /// Unlock the running broker.
    Unlock {
        /// Use the recovery key to unlock; does not reset the password.
        #[arg(long)]
        recovery: bool,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Lock the running broker and revoke all sessions.
    Lock,
    /// Show broker status.
    Status,
    /// Stop the running broker (step-up proof required while unlocked).
    Shutdown {
        #[arg(long)]
        password_stdin: bool,
    },
    /// Credential administration.
    #[command(subcommand)]
    Credential(CredentialCommand),
    /// Fixed action administration.
    #[command(subcommand)]
    Action(ActionCommand),
    /// Capability session administration.
    #[command(subcommand)]
    Session(SessionCommand),
    /// Typed authorization policy administration.
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Execute a fixed action through the agent channel.
    Execute {
        /// ACTION_ID@VERSION
        action: String,
        /// Capability token, or '-' to read it from stdin (recommended).
        #[arg(long, allow_hyphen_values = true)]
        capability: String,
        #[arg(long)]
        body_file: Option<PathBuf>,
        #[arg(long)]
        content_type: Option<String>,
        /// Extra header NAME:VALUE (repeatable; must be on the action's allowlist).
        #[arg(long = "header")]
        headers: Vec<String>,
    },
    /// Write an encrypted backup (broker must be unlocked).
    Backup {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Subcommand)]
enum CredentialCommand {
    /// Add a credential (prompts for step-up password and the value).
    Add {
        label: String,
        /// Read step-up password (line 1) and credential value (line 2) from stdin.
        #[arg(long)]
        stdin_secrets: bool,
    },
    /// Add an encrypted GitHub App Installation profile from a JSON file.
    AddGithubApp {
        label: String,
        /// JSON containing the private key and fixed GitHub identifiers.
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        password_stdin: bool,
    },
    List,
    Rotate {
        credential_id: String,
        /// Read step-up password (line 1) and credential value (line 2) from stdin.
        #[arg(long)]
        stdin_secrets: bool,
    },
    Revoke {
        credential_id: String,
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Subcommand)]
enum ActionCommand {
    /// Create an action from a JSON definition file.
    Create {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Create a new immutable version of an existing action.
    Update {
        action_id: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        password_stdin: bool,
    },
    List,
    Disable {
        action_id: String,
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Subcommand)]
enum SessionCommand {
    /// Issue a capability session for one or more pinned actions.
    Create {
        /// ACTION_ID@VERSION (repeatable).
        #[arg(long = "action", required = true)]
        actions: Vec<String>,
        #[arg(long, default_value = "1h")]
        ttl: String,
        #[arg(long, default_value_t = 100)]
        max_uses: u32,
        #[arg(long)]
        password_stdin: bool,
    },
    Revoke {
        session_id: String,
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Validate and activate a complete in-memory policy snapshot.
    Activate {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Show the active policy version and digest.
    Status,
}

fn main() {
    let cli = Cli::parse();
    let state_dir = match commands::resolve_state_dir(cli.state_dir) {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: {}", err.message);
            std::process::exit(err.exit_code());
        }
    };
    let agent_socket = cli
        .agent_socket
        .unwrap_or_else(|| state_dir.join("runtime").join("agent.sock"));
    let result = match cli.command {
        Command::Init { password_stdin } => {
            commands::delegate_rekeyd(&state_dir, "init", &[], password_stdin)
        }
        Command::Serve { idle_lock } => commands::delegate_rekeyd(
            &state_dir,
            "serve",
            &["--idle-lock".to_owned(), idle_lock],
            false,
        ),
        Command::Restore {
            input,
            recovery,
            password_stdin,
            sha256,
        } => {
            let mut args = vec!["--input".to_owned(), input.display().to_string()];
            if recovery {
                args.push("--recovery".to_owned());
            }
            args.push("--sha256".to_owned());
            args.push(sha256);
            commands::delegate_rekeyd(&state_dir, "restore", &args, password_stdin)
        }
        Command::Unlock {
            recovery,
            password_stdin,
        } => commands::unlock(&state_dir, recovery, password_stdin),
        Command::Lock => commands::lock(&state_dir),
        Command::Status => commands::status(&state_dir),
        Command::Shutdown { password_stdin } => commands::shutdown(&state_dir, password_stdin),
        Command::Credential(cmd) => match cmd {
            CredentialCommand::Add {
                label,
                stdin_secrets,
            } => commands::credential_add(&state_dir, &label, stdin_secrets),
            CredentialCommand::AddGithubApp {
                label,
                file,
                password_stdin,
            } => commands::credential_add_github_app(&state_dir, &label, &file, password_stdin),
            CredentialCommand::List => commands::credential_list(&state_dir),
            CredentialCommand::Rotate {
                credential_id,
                stdin_secrets,
            } => commands::credential_rotate(&state_dir, &credential_id, stdin_secrets),
            CredentialCommand::Revoke {
                credential_id,
                password_stdin,
            } => commands::credential_revoke(&state_dir, &credential_id, password_stdin),
        },
        Command::Action(cmd) => match cmd {
            ActionCommand::Create {
                file,
                password_stdin,
            } => commands::action_create(&state_dir, &file, password_stdin),
            ActionCommand::Update {
                action_id,
                file,
                password_stdin,
            } => commands::action_update(&state_dir, &action_id, &file, password_stdin),
            ActionCommand::List => commands::action_list(&state_dir),
            ActionCommand::Disable {
                action_id,
                password_stdin,
            } => commands::action_disable(&state_dir, &action_id, password_stdin),
        },
        Command::Session(cmd) => match cmd {
            SessionCommand::Create {
                actions,
                ttl,
                max_uses,
                password_stdin,
            } => commands::session_create(&state_dir, &actions, &ttl, max_uses, password_stdin),
            SessionCommand::Revoke {
                session_id,
                password_stdin,
            } => commands::session_revoke(&state_dir, &session_id, password_stdin),
        },
        Command::Policy(cmd) => match cmd {
            PolicyCommand::Activate {
                file,
                password_stdin,
            } => commands::policy_activate(&state_dir, &file, password_stdin),
            PolicyCommand::Status => commands::policy_status(&state_dir),
        },
        Command::Execute {
            action,
            capability,
            body_file,
            content_type,
            headers,
        } => commands::execute(
            &agent_socket,
            &action,
            &capability,
            body_file.as_deref(),
            content_type,
            &headers,
        ),
        Command::Backup {
            output,
            password_stdin,
        } => commands::backup(&state_dir, &output, password_stdin),
    };
    if let Err(err) = result {
        eprintln!("error [{}]: {}", err.code, err.message);
        std::process::exit(err.exit_code());
    }
}
