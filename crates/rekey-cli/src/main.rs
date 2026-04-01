mod cmd_add;
mod cmd_dashboard;
mod cmd_destroy;
mod cmd_env;
mod cmd_init;
mod cmd_list;
mod cmd_remove;
mod cmd_rotate;
mod cmd_start;
mod cmd_status;
mod cmd_stop;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "rekey", about = "AI agent API key proxy", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Add {
        name: String,
        value: String,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        header: Option<String>,
    },
    List,
    Remove {
        name: String,
    },
    Rotate {
        name: String,
        value: String,
    },
    Start {
        #[arg(short, long)]
        daemon: bool,
        #[arg(short, long, default_value = "10800")]
        port: u16,
    },
    Stop,
    Status,
    Env,
    Dashboard,
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
