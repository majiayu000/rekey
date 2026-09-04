//! rekey: IPC-only admin/agent CLI. Offline bootstrap (init/restore) and the
//! broker itself live in `rekeyd`; this binary delegates those subcommands to
//! it so the CLI process never holds database or crypto capability.

mod client;
mod commands;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use rekey_domain::audit::{AUDIT_PAGE_DEFAULT_LIMIT, AUDIT_PAGE_MAX_LIMIT, AuditQuery};
use rekey_domain::ids::{ActionId, CredentialId, RequestId, SessionId};

#[derive(Args)]
struct StepUpArgs {
    /// Use the recovery key for step-up proof; does not reset the password.
    #[arg(long)]
    recovery: bool,
    /// Read the step-up proof from stdin instead of the TTY.
    #[arg(long)]
    password_stdin: bool,
}

#[derive(Args)]
struct PolicyStepUpArgs {
    /// Use the recovery key for step-up proof; does not reset the password.
    #[arg(long)]
    recovery: bool,
    /// Read the step-up proof from stdin instead of the TTY.
    #[arg(long)]
    step_up_stdin: bool,
}

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
    /// Launch an Agent command with deny-by-default IP egress (delegates to rekeyd).
    AgentRun {
        /// Read the capability token from stdin (first line).
        #[arg(long)]
        capability_stdin: bool,
        #[arg(last = true, required = true)]
        command: Vec<std::ffi::OsString>,
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
        #[command(flatten)]
        step_up: StepUpArgs,
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
    /// Prepare a signed-approval challenge.
    #[command(subcommand)]
    Approval(ApprovalCommand),
    /// Vault password lifecycle.
    #[command(subcommand)]
    Password(PasswordCommand),
    /// Recovery-key lifecycle.
    #[command(subcommand)]
    Recovery(RecoveryCommand),
    /// Query or export the local audit trail.
    #[command(subcommand)]
    Audit(AuditCommand),
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
        /// Signed approval grant JSON file (repeatable, at most two).
        #[arg(long = "approval")]
        approvals: Vec<PathBuf>,
    },
    /// Write an encrypted backup (broker must be unlocked).
    Backup {
        #[arg(long)]
        output: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
}

#[derive(Subcommand)]
enum CredentialCommand {
    /// Add a credential (prompts for step-up password and the value).
    Add {
        label: String,
        /// Use the recovery key for step-up proof; does not reset the password.
        #[arg(long)]
        recovery: bool,
        /// Read step-up proof (line 1) and credential value (line 2) from stdin.
        #[arg(long)]
        stdin_secrets: bool,
    },
    /// Add an encrypted GitHub App Installation profile from a JSON file.
    AddGithubApp {
        label: String,
        /// JSON containing the private key and fixed GitHub identifiers.
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Add a closed Vault KV v2 fixed-version source profile.
    AddVaultKv {
        label: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Add a closed one-shot Vault dynamic lease source profile.
    AddVaultDynamic {
        label: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    List,
    Rotate {
        credential_id: String,
        /// Use the recovery key for step-up proof; does not reset the password.
        #[arg(long)]
        recovery: bool,
        /// Read step-up proof (line 1) and credential value (line 2) from stdin.
        #[arg(long)]
        stdin_secrets: bool,
    },
    /// Rotate a GitHub App Installation profile from a JSON file.
    RotateGithubApp {
        credential_id: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Rotate a Vault KV v2 fixed-version source profile.
    RotateVaultKv {
        credential_id: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Rotate a one-shot Vault dynamic lease source profile.
    RotateVaultDynamic {
        credential_id: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Apply an authenticated installation_repositories webhook delivery.
    ApplyGithubWebhook {
        credential_id: String,
        #[arg(long)]
        expected_version: u64,
        #[arg(long)]
        event: String,
        #[arg(long)]
        delivery: String,
        #[arg(long)]
        signature: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    Revoke {
        credential_id: String,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
}

#[derive(Subcommand)]
enum ActionCommand {
    /// Create an action from a JSON definition file.
    Create {
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Create a new immutable version of an existing action.
    Update {
        action_id: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    List,
    Disable {
        action_id: String,
        #[command(flatten)]
        step_up: StepUpArgs,
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
        /// Read a workload JWT from stdin and mint through the Agent socket.
        #[arg(long, conflicts_with_all = ["recovery", "password_stdin"])]
        workload_token_stdin: bool,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    Revoke {
        session_id: String,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Install the vault's immutable policy signer trust root.
    #[command(subcommand)]
    Trust(PolicyTrustCommand),
    /// Validate, verify, persist, and activate a signed policy bundle.
    Activate {
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: PolicyStepUpArgs,
    },
    /// Show the active policy version and digest.
    Status,
}

#[derive(Subcommand)]
enum PolicyTrustCommand {
    Install {
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: PolicyStepUpArgs,
    },
}

#[derive(Subcommand)]
enum ApprovalCommand {
    Prepare {
        /// ACTION_ID@VERSION
        action: String,
        /// Capability token, or '-' to read it from stdin (recommended).
        #[arg(long, allow_hyphen_values = true)]
        capability: String,
        #[arg(long)]
        body_file: Option<PathBuf>,
        #[arg(long)]
        content_type: Option<String>,
        #[arg(long = "header")]
        headers: Vec<String>,
    },
}

#[derive(Subcommand)]
enum PasswordCommand {
    /// Replace the password; use --recovery when the old password is lost.
    Change {
        #[arg(long)]
        recovery: bool,
        /// Read step-up proof (line 1) and new password (line 2) from stdin.
        #[arg(long)]
        stdin_secrets: bool,
    },
}

#[derive(Subcommand)]
enum RecoveryCommand {
    /// Replace the recovery key and display the new key once.
    Rotate {
        /// Read the required password proof from stdin.
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Args)]
struct AuditFilterArgs {
    #[arg(long)]
    request: Option<RequestId>,
    #[arg(long)]
    session: Option<SessionId>,
    #[arg(long)]
    action: Option<ActionId>,
    #[arg(long)]
    credential: Option<CredentialId>,
    #[arg(long)]
    outcome: Option<String>,
    #[arg(long)]
    since_ms: Option<i64>,
    #[arg(long)]
    until_ms: Option<i64>,
}

impl AuditFilterArgs {
    fn into_query(
        self,
        snapshot_max_sequence: Option<u64>,
        before_sequence: Option<u64>,
        limit: u32,
    ) -> AuditQuery {
        AuditQuery {
            request_id: self.request,
            session_id: self.session,
            action_id: self.action,
            credential_id: self.credential,
            outcome: self.outcome,
            since_ms: self.since_ms,
            until_ms: self.until_ms,
            snapshot_max_sequence,
            before_sequence,
            limit,
        }
    }
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Print one bounded page of redacted audit events.
    List {
        #[command(flatten)]
        filters: AuditFilterArgs,
        #[arg(long)]
        snapshot_max_sequence: Option<u64>,
        #[arg(long)]
        before_sequence: Option<u64>,
        #[arg(long, default_value_t = AUDIT_PAGE_DEFAULT_LIMIT, value_parser = clap::value_parser!(u32).range(1..=i64::from(AUDIT_PAGE_MAX_LIMIT)))]
        limit: u32,
    },
    /// Write a complete stable snapshot as a new mode-0600 JSONL file.
    Export {
        #[arg(long)]
        output: PathBuf,
        #[command(flatten)]
        filters: AuditFilterArgs,
    },
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
            &["--idle-lock".into(), idle_lock.into()],
            false,
        ),
        Command::Restore {
            input,
            recovery,
            password_stdin,
            sha256,
        } => {
            let mut args = vec!["--input".into(), input.into_os_string()];
            if recovery {
                args.push("--recovery".into());
            }
            args.push("--sha256".into());
            args.push(sha256.into());
            commands::delegate_rekeyd(&state_dir, "restore", &args, password_stdin)
        }
        Command::AgentRun {
            capability_stdin,
            command,
        } => commands::delegate_agent_run(&state_dir, &agent_socket, capability_stdin, command),
        Command::Unlock {
            recovery,
            password_stdin,
        } => commands::unlock(&state_dir, recovery, password_stdin),
        Command::Lock => commands::lock(&state_dir),
        Command::Status => commands::status(&state_dir),
        Command::Shutdown { step_up } => {
            commands::shutdown(&state_dir, step_up.recovery, step_up.password_stdin)
        }
        Command::Credential(cmd) => match cmd {
            CredentialCommand::Add {
                label,
                recovery,
                stdin_secrets,
            } => commands::credential_add(&state_dir, &label, recovery, stdin_secrets),
            CredentialCommand::AddGithubApp {
                label,
                file,
                step_up,
            } => commands::credential_add_github_app(
                &state_dir,
                &label,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            CredentialCommand::AddVaultKv {
                label,
                file,
                step_up,
            } => commands::credential_add_vault_kv(
                &state_dir,
                &label,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            CredentialCommand::AddVaultDynamic {
                label,
                file,
                step_up,
            } => commands::credential_add_vault_dynamic(
                &state_dir,
                &label,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            CredentialCommand::List => commands::credential_list(&state_dir),
            CredentialCommand::Rotate {
                credential_id,
                recovery,
                stdin_secrets,
            } => commands::credential_rotate(&state_dir, &credential_id, recovery, stdin_secrets),
            CredentialCommand::RotateGithubApp {
                credential_id,
                file,
                step_up,
            } => commands::credential_rotate_github_app(
                &state_dir,
                &credential_id,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            CredentialCommand::RotateVaultKv {
                credential_id,
                file,
                step_up,
            } => commands::credential_rotate_vault_kv(
                &state_dir,
                &credential_id,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            CredentialCommand::RotateVaultDynamic {
                credential_id,
                file,
                step_up,
            } => commands::credential_rotate_vault_dynamic(
                &state_dir,
                &credential_id,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            CredentialCommand::ApplyGithubWebhook {
                credential_id,
                expected_version,
                event,
                delivery,
                signature,
                file,
                step_up,
            } => commands::credential_apply_github_webhook(
                &state_dir,
                &credential_id,
                expected_version,
                &event,
                &delivery,
                &signature,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            CredentialCommand::Revoke {
                credential_id,
                step_up,
            } => commands::credential_revoke(
                &state_dir,
                &credential_id,
                step_up.recovery,
                step_up.password_stdin,
            ),
        },
        Command::Action(cmd) => match cmd {
            ActionCommand::Create { file, step_up } => {
                commands::action_create(&state_dir, &file, step_up.recovery, step_up.password_stdin)
            }
            ActionCommand::Update {
                action_id,
                file,
                step_up,
            } => commands::action_update(
                &state_dir,
                &action_id,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            ActionCommand::List => commands::action_list(&state_dir),
            ActionCommand::Disable { action_id, step_up } => commands::action_disable(
                &state_dir,
                &action_id,
                step_up.recovery,
                step_up.password_stdin,
            ),
        },
        Command::Session(cmd) => match cmd {
            SessionCommand::Create {
                actions,
                ttl,
                max_uses,
                workload_token_stdin,
                step_up,
            } => {
                if workload_token_stdin {
                    commands::workload_session_create(&agent_socket, &actions, &ttl, max_uses)
                } else {
                    commands::session_create(
                        &state_dir,
                        &actions,
                        &ttl,
                        max_uses,
                        step_up.recovery,
                        step_up.password_stdin,
                    )
                }
            }
            SessionCommand::Revoke {
                session_id,
                step_up,
            } => commands::session_revoke(
                &state_dir,
                &session_id,
                step_up.recovery,
                step_up.password_stdin,
            ),
        },
        Command::Policy(cmd) => match cmd {
            PolicyCommand::Trust(PolicyTrustCommand::Install { file, step_up }) => {
                commands::policy_trust_install(
                    &state_dir,
                    &file,
                    step_up.recovery,
                    step_up.step_up_stdin,
                )
            }
            PolicyCommand::Activate { file, step_up } => commands::policy_activate(
                &state_dir,
                &file,
                step_up.recovery,
                step_up.step_up_stdin,
            ),
            PolicyCommand::Status => commands::policy_status(&state_dir),
        },
        Command::Approval(ApprovalCommand::Prepare {
            action,
            capability,
            body_file,
            content_type,
            headers,
        }) => commands::approval_prepare(
            &agent_socket,
            &action,
            &capability,
            body_file.as_deref(),
            content_type,
            &headers,
        ),
        Command::Password(PasswordCommand::Change {
            recovery,
            stdin_secrets,
        }) => commands::password_change(&state_dir, recovery, stdin_secrets),
        Command::Recovery(RecoveryCommand::Rotate { password_stdin }) => {
            commands::recovery_rotate(&state_dir, password_stdin)
        }
        Command::Audit(AuditCommand::List {
            filters,
            snapshot_max_sequence,
            before_sequence,
            limit,
        }) => commands::audit_list(
            &state_dir,
            filters.into_query(snapshot_max_sequence, before_sequence, limit),
        ),
        Command::Audit(AuditCommand::Export { output, filters }) => commands::audit_export(
            &state_dir,
            &output,
            filters.into_query(None, None, AUDIT_PAGE_MAX_LIMIT),
        ),
        Command::Execute {
            action,
            capability,
            body_file,
            content_type,
            headers,
            approvals,
        } => commands::execute(
            &agent_socket,
            &action,
            &capability,
            body_file.as_deref(),
            content_type,
            &headers,
            &approvals,
        ),
        Command::Backup { output, step_up } => commands::backup(
            &state_dir,
            &output,
            step_up.recovery,
            step_up.password_stdin,
        ),
    };
    if let Err(err) = result {
        eprintln!("error [{}]: {}", err.code, err.message);
        std::process::exit(err.exit_code());
    }
}
