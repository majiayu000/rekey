//! rekey: IPC-only admin/agent CLI. Offline bootstrap (init/restore) and the
//! broker itself live in `rekeyd`; this binary delegates those subcommands to
//! it so the CLI process never holds database or crypto capability.

mod client;
mod commands;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
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
struct RequestArgs {
    #[arg(long)]
    body_file: Option<PathBuf>,
    #[arg(long)]
    content_type: Option<String>,
    /// Extra header NAME:VALUE, restricted by the registered Action.
    #[arg(long = "header")]
    headers: Vec<String>,
    /// Registered path parameter NAME=VALUE (repeatable).
    #[arg(long = "param")]
    params: Vec<String>,
    /// Registered query parameter NAME=VALUE (repeatable).
    #[arg(long = "query")]
    query: Vec<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum BuiltinTemplateName {
    Anthropic,
    Openai,
    GithubPat,
}

impl From<BuiltinTemplateName> for rekey_domain::ipc::TemplateSource {
    fn from(value: BuiltinTemplateName) -> Self {
        match value {
            BuiltinTemplateName::Anthropic => Self::Anthropic {},
            BuiltinTemplateName::Openai => Self::OpenAi {},
            BuiltinTemplateName::GithubPat => Self::GitHubPat {},
        }
    }
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
    /// Explicit private OIDC management session file.
    #[arg(long, global = true)]
    #[cfg(feature = "lab")]
    admin_session_file: Option<PathBuf>,
}

#[cfg(feature = "lab")]
#[derive(Subcommand)]
enum OidcLoginCommand {
    Begin,
    Finish {
        #[arg(long)]
        flow_id: String,
        #[arg(long)]
        session_file: PathBuf,
    },
    Cancel {
        #[arg(long)]
        flow_id: String,
    },
    Logout {
        #[arg(long)]
        session_file: PathBuf,
    },
}

#[derive(Subcommand)]
enum Command {
    /// Fixed-node OIDC administrator login lifecycle.
    #[command(subcommand)]
    #[cfg(feature = "lab")]
    OidcLogin(OidcLoginCommand),
    /// Initialize a new vault (delegates to rekeyd).
    Init {
        /// Immutable policy signing mode for this vault.
        #[arg(long, value_parser = ["personal", "team"])]
        mode: String,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Run the broker in the foreground (delegates to rekeyd).
    Serve {
        #[arg(long)]
        #[cfg(feature = "lab")]
        oidc_admin_profile: Option<PathBuf>,
        #[arg(long, default_value = "7d")]
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
    /// Desktop admin login; proof is read only from stdin, token written to stdout.
    DesktopLogin {
        #[arg(long)]
        recovery: bool,
    },
    /// Remember this desktop for seven days; proof on stdin, key on stdout.
    DesktopRemember {
        #[arg(long)]
        recovery: bool,
    },
    /// Resume a remembered desktop; key on stdin, session on stdout.
    DesktopResume,
    /// Save an API key; desktop token and value are read as two stdin lines.
    DesktopAdd { label: String },
    /// Reveal a current credential with a fresh password or recovery proof.
    DesktopReveal {
        credential_id: String,
        #[command(flatten)]
        step_up: StepUpArgs,
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
    Status {
        /// Observe without resetting the idle-lock timer.
        #[arg(long)]
        passive: bool,
    },
    /// Read local monitoring counters without resetting the idle-lock timer.
    #[cfg(feature = "lab")]
    Metrics {
        /// Print Prometheus text exposition instead of JSON.
        #[arg(long)]
        prometheus: bool,
        /// Atomically publish rekey.prom in an existing controlled directory.
        #[arg(long, requires = "prometheus")]
        textfile_dir: Option<PathBuf>,
    },
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
    /// Inspect and install authenticated provider templates.
    #[command(subcommand)]
    Template(TemplateCommand),
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
    /// Vault key maintenance (DEK rotation only; VRK and old backups are unchanged).
    #[command(subcommand)]
    Key(KeyCommand),
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
        #[command(flatten)]
        request: RequestArgs,
        /// Signed approval grant JSON file (repeatable, at most two).
        #[arg(long = "approval")]
        approvals: Vec<PathBuf>,
    },
    /// Stream a fixed Anthropic text Action; partial text is not success.
    ExecuteTextStream {
        /// ACTION_ID@VERSION
        action: String,
        #[arg(long, allow_hyphen_values = true)]
        capability: String,
        #[arg(long)]
        body_file: PathBuf,
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
    #[cfg(feature = "lab")]
    AddVaultKv {
        label: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Add a closed Keycloak standard token exchange profile.
    #[cfg(feature = "lab")]
    AddKeycloak {
        label: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Add a closed one-shot Vault dynamic lease source profile.
    #[cfg(feature = "lab")]
    AddVaultDynamic {
        label: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Add a fixed GCP Secret Manager numeric version source profile.
    #[cfg(feature = "lab")]
    AddGcpSecretManager {
        label: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Rotate a fixed GCP Secret Manager source profile.
    #[cfg(feature = "lab")]
    RotateGcpSecretManager {
        credential_id: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Add a fixed Azure Key Vault pinned version source profile.
    #[cfg(feature = "lab")]
    AddAzureKeyVault {
        label: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Rotate a fixed Azure Key Vault source profile.
    #[cfg(feature = "lab")]
    RotateAzureKeyVault {
        credential_id: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Add one exact encrypted macOS file-Keychain reference.
    #[cfg(feature = "lab")]
    AddMacosKeychain {
        label: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Rotate one exact macOS file-Keychain reference.
    #[cfg(feature = "lab")]
    RotateMacosKeychain {
        credential_id: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Add a fixed 1Password Connect item field source profile.
    #[command(name = "add-onepassword-connect")]
    #[cfg(feature = "lab")]
    AddOnePasswordConnect {
        label: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Rotate a fixed 1Password Connect source profile.
    #[command(name = "rotate-onepassword-connect")]
    #[cfg(feature = "lab")]
    RotateOnePasswordConnect {
        credential_id: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Add a fixed AWS Secrets Manager pinned version source profile.
    #[cfg(feature = "lab")]
    AddAwsSecretsManager {
        label: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Rotate a fixed AWS Secrets Manager source profile.
    #[cfg(feature = "lab")]
    RotateAwsSecretsManager {
        credential_id: String,
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
    #[cfg(feature = "lab")]
    RotateVaultKv {
        credential_id: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Rotate a closed Keycloak standard token exchange profile.
    #[cfg(feature = "lab")]
    RotateKeycloak {
        credential_id: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    /// Rotate a one-shot Vault dynamic lease source profile.
    #[cfg(feature = "lab")]
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
enum TemplateCommand {
    /// Inspect a built-in declaration or authenticate a signed package.
    #[command(group(clap::ArgGroup::new("source").required(true).args(["builtin", "file", "stdin_request"])))]
    Catalog {
        #[arg(long)]
        builtin: Option<BuiltinTemplateName>,
        /// JSON catalog request for generic targets or a signed package.
        #[arg(long)]
        file: Option<PathBuf>,
        /// Read one compact JSON request line from stdin.
        #[arg(long)]
        stdin_request: bool,
        #[arg(long, conflicts_with = "builtin")]
        package: Option<PathBuf>,
    },
    /// Install all selected capabilities atomically; retry creates new actions.
    Install {
        /// JSON request containing credential, bindings, capabilities and limits.
        #[arg(
            long,
            conflicts_with = "stdin_request",
            required_unless_present = "stdin_request"
        )]
        file: Option<PathBuf>,
        /// Read proof then compact JSON as two lines from one stdin snapshot.
        #[arg(long, conflicts_with = "file", requires = "password_stdin")]
        stdin_request: bool,
        /// Signed template package; omitted for built-in sources.
        #[arg(long)]
        package: Option<PathBuf>,
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
        #[cfg(feature = "lab")]
        workload_token_stdin: bool,
        /// Reissue for an explicitly authorized principal after policy replacement.
        #[arg(long)]
        #[cfg_attr(feature = "lab", arg(conflicts_with = "workload_token_stdin"))]
        principal: Option<String>,
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
        #[arg(long)]
        expected_vault_id: String,
        #[arg(long)]
        expected_trust_sha256: String,
        #[command(flatten)]
        step_up: PolicyStepUpArgs,
    },
    /// Show the active policy version and digest.
    Status,
}

#[derive(Subcommand)]
enum PolicyTrustCommand {
    Install {
        #[arg(
            long,
            conflicts_with = "stdin_request",
            required_unless_present = "stdin_request"
        )]
        file: Option<PathBuf>,
        /// Read proof then the compact trust document through one stdin pipe.
        #[arg(long, conflicts_with = "file", requires = "step_up_stdin")]
        stdin_request: bool,
        #[command(flatten)]
        step_up: PolicyStepUpArgs,
    },
}

#[derive(Subcommand)]
enum ApprovalCommand {
    /// Pin this vault's approval-origin public key.
    Origin,
    /// List unused in-memory approval challenges.
    Pending,
    /// Print the origin-signed envelope for a pending approval request.
    Get { approval_request_id: String },
    Prepare {
        /// ACTION_ID@VERSION
        action: String,
        /// Capability token, or '-' to read it from stdin (recommended).
        #[arg(long, allow_hyphen_values = true)]
        capability: String,
        #[command(flatten)]
        request: RequestArgs,
    },
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Rotate the vault root key while locked, requiring both current factors.
    RotateVrk {
        /// Read current password and recovery key as exactly two stdin lines.
        #[arg(long)]
        stdin_secrets: bool,
    },
    /// Reseal all credential versions under fresh DEKs, preserving their values.
    RotateDek {
        #[command(flatten)]
        step_up: StepUpArgs,
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
    /// Configure or inspect automatic pruning while the vault is unlocked.
    #[command(subcommand)]
    Retention(AuditRetentionCommand),
    /// Delete complete unapproved execution groups strictly older than the cutoff.
    Prune {
        #[arg(
            long,
            required_unless_present = "older_than_days",
            conflicts_with = "older_than_days"
        )]
        before_ms: Option<i64>,
        /// Select complete groups older than this many 24-hour days; requires step-up on every call.
        #[arg(long, required_unless_present = "before_ms", conflicts_with = "before_ms", value_parser = clap::value_parser!(u64).range(1..))]
        older_than_days: Option<u64>,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
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

#[derive(Subcommand)]
enum AuditRetentionCommand {
    Set {
        #[arg(long, required_unless_present = "disable", conflicts_with = "disable", value_parser = clap::value_parser!(u64).range(1..))]
        days: Option<u64>,
        #[arg(long, required_unless_present = "days", conflicts_with = "days")]
        disable: bool,
        #[command(flatten)]
        step_up: StepUpArgs,
    },
    Status,
}

fn main() {
    let cli = Cli::parse();
    #[cfg(feature = "lab")]
    client::configure_admin_session_file(cli.admin_session_file);
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
        #[cfg(feature = "lab")]
        Command::OidcLogin(command) => match command {
            OidcLoginCommand::Begin => commands::oidc_begin(&state_dir),
            OidcLoginCommand::Finish {
                flow_id,
                session_file,
            } => commands::oidc_finish(&state_dir, &flow_id, &session_file),
            OidcLoginCommand::Cancel { flow_id } => commands::oidc_cancel(&state_dir, &flow_id),
            OidcLoginCommand::Logout { session_file } => {
                commands::oidc_logout(&state_dir, &session_file)
            }
        },
        Command::DesktopRemember { recovery } => {
            commands::desktop_restore_access(&state_dir, false, recovery)
        }
        Command::DesktopResume => commands::desktop_restore_access(&state_dir, true, false),
        Command::DesktopLogin { recovery } => commands::desktop_login(&state_dir, recovery),
        Command::DesktopAdd { label } => commands::desktop_add(&state_dir, &label),
        Command::DesktopReveal {
            credential_id,
            step_up,
        } => commands::desktop_reveal(
            &state_dir,
            &credential_id,
            step_up.recovery,
            step_up.password_stdin,
        ),
        Command::Init {
            mode,
            password_stdin,
        } => commands::delegate_rekeyd(
            &state_dir,
            "init",
            &["--mode".into(), mode.into()],
            password_stdin,
        ),
        Command::Serve {
            idle_lock,
            #[cfg(feature = "lab")]
            oidc_admin_profile,
        } => {
            #[allow(unused_mut)]
            let mut args = vec!["--idle-lock".into(), idle_lock.into()];
            #[cfg(feature = "lab")]
            if let Some(profile) = oidc_admin_profile {
                args.push("--oidc-admin-profile".into());
                args.push(profile.into_os_string());
            }
            commands::delegate_rekeyd(&state_dir, "serve", &args, false)
        }
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
        Command::Status { passive } => commands::status(&state_dir, passive),
        #[cfg(feature = "lab")]
        Command::Metrics {
            prometheus,
            textfile_dir,
        } => commands::metrics(&state_dir, prometheus, textfile_dir.as_deref()),
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
            #[cfg(feature = "lab")]
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
            #[cfg(feature = "lab")]
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
            #[cfg(feature = "lab")]
            CredentialCommand::AddKeycloak {
                label,
                file,
                step_up,
            } => commands::credential_add_keycloak(
                &state_dir,
                &label,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            #[cfg(feature = "lab")]
            CredentialCommand::RotateKeycloak {
                credential_id,
                file,
                step_up,
            } => commands::credential_rotate_keycloak(
                &state_dir,
                &credential_id,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            #[cfg(feature = "lab")]
            CredentialCommand::AddGcpSecretManager {
                label,
                file,
                step_up,
            } => commands::credential_add_gcp_secret_manager(
                &state_dir,
                &label,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            #[cfg(feature = "lab")]
            CredentialCommand::RotateGcpSecretManager {
                credential_id,
                file,
                step_up,
            } => commands::credential_rotate_gcp_secret_manager(
                &state_dir,
                &credential_id,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            #[cfg(feature = "lab")]
            CredentialCommand::AddAzureKeyVault {
                label,
                file,
                step_up,
            } => commands::credential_add_azure_key_vault(
                &state_dir,
                &label,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            #[cfg(feature = "lab")]
            CredentialCommand::RotateAzureKeyVault {
                credential_id,
                file,
                step_up,
            } => commands::credential_rotate_azure_key_vault(
                &state_dir,
                &credential_id,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            #[cfg(feature = "lab")]
            CredentialCommand::AddMacosKeychain {
                label,
                file,
                step_up,
            } => commands::credential_add_macos_keychain(
                &state_dir,
                &label,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            #[cfg(feature = "lab")]
            CredentialCommand::RotateMacosKeychain {
                credential_id,
                file,
                step_up,
            } => commands::credential_rotate_macos_keychain(
                &state_dir,
                &credential_id,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            #[cfg(feature = "lab")]
            CredentialCommand::AddOnePasswordConnect {
                label,
                file,
                step_up,
            } => commands::credential_add_onepassword_connect(
                &state_dir,
                &label,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            #[cfg(feature = "lab")]
            CredentialCommand::RotateOnePasswordConnect {
                credential_id,
                file,
                step_up,
            } => commands::credential_rotate_onepassword_connect(
                &state_dir,
                &credential_id,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            #[cfg(feature = "lab")]
            CredentialCommand::AddAwsSecretsManager {
                label,
                file,
                step_up,
            } => commands::credential_add_aws_secrets_manager(
                &state_dir,
                &label,
                &file,
                step_up.recovery,
                step_up.password_stdin,
            ),
            #[cfg(feature = "lab")]
            CredentialCommand::RotateAwsSecretsManager {
                credential_id,
                file,
                step_up,
            } => commands::credential_rotate_aws_secrets_manager(
                &state_dir,
                &credential_id,
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
            #[cfg(feature = "lab")]
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
            #[cfg(feature = "lab")]
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
        Command::Template(command) => match command {
            TemplateCommand::Catalog {
                builtin,
                file,
                stdin_request,
                package,
            } => commands::template_catalog(
                &state_dir,
                builtin.map(Into::into),
                file.as_deref(),
                stdin_request,
                package.as_deref(),
            ),
            TemplateCommand::Install {
                file,
                stdin_request,
                package,
                step_up,
            } => commands::template_install(
                &state_dir,
                file.as_deref(),
                stdin_request,
                package.as_deref(),
                step_up.recovery,
                step_up.password_stdin,
            ),
        },
        Command::Session(cmd) => match cmd {
            SessionCommand::Create {
                actions,
                ttl,
                max_uses,
                #[cfg(feature = "lab")]
                workload_token_stdin,
                principal,
                step_up,
            } => match () {
                #[cfg(feature = "lab")]
                _ if workload_token_stdin => {
                    commands::workload_session_create(&agent_socket, &actions, &ttl, max_uses)
                }
                _ => commands::session_create(
                    &state_dir,
                    &actions,
                    &ttl,
                    max_uses,
                    principal.as_deref(),
                    step_up.recovery,
                    step_up.password_stdin,
                ),
            },
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
            PolicyCommand::Trust(PolicyTrustCommand::Install {
                file,
                stdin_request,
                step_up,
            }) => commands::policy_trust_install(
                &state_dir,
                file.as_deref(),
                stdin_request,
                step_up.recovery,
                step_up.step_up_stdin,
            ),
            PolicyCommand::Activate {
                file,
                expected_vault_id,
                expected_trust_sha256,
                step_up,
            } => commands::policy_activate(
                &state_dir,
                &file,
                &expected_vault_id,
                &expected_trust_sha256,
                step_up.recovery,
                step_up.step_up_stdin,
            ),
            PolicyCommand::Status => commands::policy_status(&state_dir),
        },
        Command::Approval(ApprovalCommand::Origin) => commands::approval_origin(&state_dir),
        Command::Approval(ApprovalCommand::Pending) => commands::approval_pending(&state_dir),
        Command::Approval(ApprovalCommand::Get {
            approval_request_id,
        }) => commands::approval_get(&state_dir, &approval_request_id),
        Command::Approval(ApprovalCommand::Prepare {
            action,
            capability,
            request,
        }) => commands::approval_prepare(&agent_socket, &action, &capability, &request),
        Command::Key(KeyCommand::RotateVrk { stdin_secrets }) => {
            commands::key_rotate_vrk(&state_dir, stdin_secrets)
        }
        Command::Key(KeyCommand::RotateDek { step_up }) => {
            commands::key_rotate_dek(&state_dir, step_up.recovery, step_up.password_stdin)
        }
        Command::Password(PasswordCommand::Change {
            recovery,
            stdin_secrets,
        }) => commands::password_change(&state_dir, recovery, stdin_secrets),
        Command::Recovery(RecoveryCommand::Rotate { password_stdin }) => {
            commands::recovery_rotate(&state_dir, password_stdin)
        }
        Command::Audit(AuditCommand::Retention(AuditRetentionCommand::Set {
            days,
            disable: _,
            step_up,
        })) => commands::audit_retention_set(
            &state_dir,
            days,
            step_up.recovery,
            step_up.password_stdin,
        ),
        Command::Audit(AuditCommand::Retention(AuditRetentionCommand::Status)) => {
            commands::audit_retention_status(&state_dir)
        }
        Command::Audit(AuditCommand::Prune {
            before_ms,
            older_than_days,
            step_up,
        }) => commands::audit_prune(
            &state_dir,
            before_ms,
            older_than_days,
            step_up.recovery,
            step_up.password_stdin,
        ),
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
            request,
            approvals,
        } => commands::execute(&agent_socket, &action, &capability, &request, &approvals),
        Command::ExecuteTextStream {
            action,
            capability,
            body_file,
            approvals,
        } => commands::execute_text_stream(
            &agent_socket,
            &action,
            &capability,
            &body_file,
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

#[cfg(test)]
mod policy_target_args_tests {
    use super::*;

    #[test]
    fn init_requires_an_explicit_supported_policy_mode() {
        assert!(Cli::try_parse_from(["rekey", "init", "--password-stdin"]).is_err());
        assert!(Cli::try_parse_from(["rekey", "init", "--mode", "automatic"]).is_err());
        for mode in ["personal", "team"] {
            assert!(Cli::try_parse_from(["rekey", "init", "--mode", mode]).is_ok());
        }
    }

    #[test]
    #[cfg(feature = "lab")]
    fn oidc_login_explicit_files_and_global_admin_session_flag_parse() {
        assert!(Cli::try_parse_from(["rekey", "oidc-login", "begin"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "rekey",
                "oidc-login",
                "finish",
                "--flow-id",
                "public-flow",
                "--session-file",
                "/private/path/session"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from(["rekey", "oidc-login", "finish", "--flow-id", "public-flow"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "rekey",
                "--admin-session-file",
                "/private/path/session",
                "metrics"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "rekey",
                "serve",
                "--oidc-admin-profile",
                "/private/path/profile"
            ])
            .is_ok()
        );
    }

    #[cfg(not(feature = "lab"))]
    #[test]
    fn default_cli_rejects_lab_entrypoints() {
        for args in [
            vec!["rekey", "metrics"],
            vec!["rekey", "oidc-login", "begin"],
            vec!["rekey", "credential", "add-vault-kv", "test"],
            vec!["rekey", "serve", "--oidc-admin-profile", "test.json"],
            vec!["rekey", "--admin-session-file", "test.json", "status"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
        assert!(Cli::try_parse_from(["rekey", "status"]).is_ok());
        assert!(Cli::try_parse_from(["rekey", "credential", "list"]).is_ok());
    }

    #[test]
    fn audit_prune_age_requires_exactly_one_positive_selector() {
        assert!(
            Cli::try_parse_from([
                "rekey",
                "audit",
                "prune",
                "--older-than-days",
                "30",
                "--password-stdin"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "rekey",
                "audit",
                "prune",
                "--before-ms",
                "100",
                "--password-stdin"
            ])
            .is_ok()
        );
        for args in [
            vec!["rekey", "audit", "prune"],
            vec![
                "rekey",
                "audit",
                "prune",
                "--before-ms",
                "100",
                "--older-than-days",
                "30",
            ],
            vec!["rekey", "audit", "prune", "--older-than-days", "0"],
            vec!["rekey", "audit", "prune", "--older-than-days", "-1"],
            vec![
                "rekey",
                "audit",
                "prune",
                "--older-than-days",
                "18446744073709551616",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn policy_activate_requires_both_public_target_flags() {
        let base = [
            "rekey",
            "policy",
            "activate",
            "--file",
            "bundle.json",
            "--step-up-stdin",
        ];
        assert!(Cli::try_parse_from(base).is_err());
        let mut args = base.to_vec();
        args.extend([
            "--expected-vault-id",
            "00112233-4455-4677-8899-aabbccddeeff",
        ]);
        assert!(Cli::try_parse_from(&args).is_err());
        args.extend([
            "--expected-trust-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ]);
        assert!(Cli::try_parse_from(&args).is_ok());
        assert!(
            Cli::try_parse_from(base.into_iter().chain([
                "--expected-trust-sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ]))
            .is_err()
        );
    }
}

#[cfg(test)]
mod retention_cli_tests {
    use super::*;
    #[test]
    fn retention_set_requires_exactly_one_explicit_selector() {
        for args in [
            vec!["rekey", "audit", "retention", "set"],
            vec!["rekey", "audit", "retention", "set", "--days", "0"],
            vec![
                "rekey",
                "audit",
                "retention",
                "set",
                "--days",
                "1",
                "--disable",
            ],
            vec!["rekey", "audit", "retention", "set", "--interval", "5"],
            vec!["rekey", "audit", "retention", "apply"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
        for args in [
            vec![
                "rekey",
                "audit",
                "retention",
                "set",
                "--days",
                "1",
                "--password-stdin",
            ],
            vec![
                "rekey",
                "audit",
                "retention",
                "set",
                "--disable",
                "--password-stdin",
            ],
            vec!["rekey", "audit", "retention", "status"],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
    }
}
