mod cmd_add;
mod cmd_dashboard;
mod cmd_destroy;
mod cmd_env;
mod cmd_init;
mod cmd_list;
mod cmd_remove;
mod cmd_request;
mod cmd_rotate;
mod cmd_start;
mod cmd_status;
mod cmd_stop;
mod cmd_store;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "rekey", about = "Encrypted credential vault for AI agents", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize vault with master password
    Init,
    /// Add an API key (auto-detects known providers)
    Add {
        name: String,
        value: String,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        header: Option<String>,
    },
    /// Store a multi-field credential (basic auth, bearer, custom headers)
    Store {
        name: String,
        #[arg(long, short = 't')]
        r#type: Option<String>,
    },
    /// Make an authenticated HTTP request (agents call this)
    Request {
        /// Credential name
        name: String,
        /// Target URL
        url: String,
        /// HTTP method
        #[arg(short = 'X', long, default_value = "GET")]
        method: String,
        /// Request body
        #[arg(short = 'd', long)]
        data: Option<String>,
        /// Extra headers (repeatable)
        #[arg(short = 'H', long)]
        header: Vec<String>,
    },
    /// List all stored credentials
    List,
    /// Remove a credential
    Remove {
        name: String,
    },
    /// Rotate an API key value
    Rotate {
        name: String,
        value: String,
    },
    /// Start the MITM proxy
    Start {
        #[arg(short, long)]
        daemon: bool,
        #[arg(short, long, default_value = "10800")]
        port: u16,
    },
    /// Stop the proxy
    Stop,
    /// Show proxy status
    Status,
    /// Print proxy environment variables
    Env,
    /// Open web dashboard
    Dashboard,
    /// Remove all rekey data
    Destroy,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rekey=info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init => cmd_init::run()?,
        Commands::Add {
            name,
            value,
            host,
            header,
        } => cmd_add::run(&name, &value, host.as_deref(), header.as_deref())?,
        Commands::Store { name, r#type } => cmd_store::run(&name, r#type.as_deref())?,
        Commands::Request {
            name,
            url,
            method,
            data,
            header,
        } => cmd_request::run(&name, &url, &method, data.as_deref(), &header)?,
        Commands::List => cmd_list::run()?,
        Commands::Remove { name } => cmd_remove::run(&name)?,
        Commands::Rotate { name, value } => cmd_rotate::run(&name, &value)?,
        Commands::Start { daemon, port } => cmd_start::run(daemon, port)?,
        Commands::Stop => cmd_stop::run()?,
        Commands::Status => cmd_status::run()?,
        Commands::Env => cmd_env::run()?,
        Commands::Dashboard => cmd_dashboard::run()?,
        Commands::Destroy => cmd_destroy::run()?,
    }

    Ok(())
}
