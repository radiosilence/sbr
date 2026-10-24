use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sbr_engine::sbr_config::Options;
use sbr_engine::{Instance, Settings};

/// Flags mirror `sing-box` so existing service files and scripts keep working.
#[derive(Parser)]
#[command(name = "sbr", version, about = "sing-box compatible proxy, in Rust")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Configuration file path
    #[arg(
        short = 'c',
        long = "config",
        global = true,
        default_value = "config.json"
    )]
    config: PathBuf,
    /// Working directory (relative paths in the config resolve against it)
    #[arg(short = 'D', long = "directory", global = true)]
    directory: Option<PathBuf>,
    /// Disable color output
    #[arg(long = "disable-color", global = true)]
    disable_color: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run service
    Run,
    /// Check configuration
    Check,
    /// Print version
    Version,
}

fn load(cli: &Cli) -> Result<Options> {
    let text = std::fs::read_to_string(&cli.config)
        .with_context(|| format!("read {}", cli.config.display()))?;
    Options::parse(&text).with_context(|| format!("decode config at {}", cli.config.display()))
}

fn init_log(o: &Options, no_color: bool) {
    if o.log.disabled {
        return;
    }
    let level = match o.log.level.as_deref() {
        Some("trace") => "trace",
        Some("debug") => "debug",
        Some("warn" | "warning") => "warn",
        Some("error" | "fatal" | "panic") => "error",
        _ => "info",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_env("SBR_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    let b = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(!no_color)
        .with_target(false);
    if o.log.timestamp {
        b.init()
    } else {
        b.without_time().init()
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(dir) = &cli.directory {
        std::env::set_current_dir(dir).with_context(|| format!("chdir {}", dir.display()))?;
    }
    match cli.cmd {
        Cmd::Version => {
            println!("sbr version {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Cmd::Check => {
            let o = load(&cli)?;
            for w in &o.warnings {
                eprintln!("WARN {w}");
            }
            // Build everything short of binding sockets, so rule-set and
            // outbound errors surface here too.
            sbr_engine::Engine::new(&o, &Settings::default())?;
            Ok(())
        }
        Cmd::Run => {
            let o = load(&cli)?;
            init_log(&o, cli.disable_color);
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let instance = Instance::start(&o, Settings::default()).await?;
                tracing::info!("sing-box compatible core started");
                shutdown_signal().await;
                tracing::info!("shutting down");
                instance.shutdown();
                anyhow::Ok(())
            })
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
