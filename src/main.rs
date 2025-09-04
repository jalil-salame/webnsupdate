use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser as _;
use config::Config;
use miette::Context;
use miette::IntoDiagnostic;
use miette::Result;
use miette::bail;
use miette::ensure;
use tokio::sync::Notify;
use tokio::sync::RwLock;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;
use tracing_subscriber::EnvFilter;

mod auth;
mod cli;
mod config;
mod nsupdate;
mod password;
mod records;
mod state;
mod update_handler;

const DEFAULT_TTL: Duration = Duration::from_secs(600);
const DEFAULT_SALT: &str = "UpdateMyDNS";

#[derive(Clone)]
struct AppState<'a> {
    /// The IN A/AAAA records that should have their IPs updated
    records: Arc<config::Records>,

    /// The TSIG key file
    key_file: Option<&'a Path>,

    /// The file where the last IP is stored
    ip_file: &'a Path,

    /// Last recorded IPs
    saved_data: Arc<RwLock<state::SavedData>>,

    /// Saved Data trigger
    trigger: Arc<Notify>,
}

impl AppState<'static> {
    fn from_args(args: &cli::Opts, config: &config::Config) -> Result<Self> {
        let cli::Opts {
            verbosity: _,
            data_dir,
            insecure,
            config_or_command: _,
        } = args;

        // Use last registered IP address if available
        let ip_file = Box::leak(data_dir.join("last-ip.json").into_boxed_path());

        let state = AppState {
            trigger: Arc::new(Notify::new()),
            records: Arc::new(config.records.clone()),
            // Load keyfile
            key_file: config
                .server
                .key_file
                .as_deref()
                .map(|path| -> Result<_> {
                    std::fs::File::open(path)
                        .into_diagnostic()
                        .wrap_err_with(|| {
                            format!("{} is not readable by the current user", path.display())
                        })?;
                    Ok(&*Box::leak(path.into()))
                })
                .transpose()?,
            ip_file,
            saved_data: Arc::new(RwLock::new(
                state::SavedData::load(ip_file)
                    .unwrap_or_else(|err| {
                        error!("failed to read state file: {err}");
                        None
                    })
                    .unwrap_or_default(),
            )),
        };

        ensure!(
            state.key_file.is_some() || *insecure,
            "a key file must be used"
        );

        Ok(state)
    }

    fn trigger_save(&self) {
        self.trigger.notify_one();
    }
}

fn load_password(path: &Path) -> Result<Box<[u8]>> {
    let pass = std::fs::read_to_string(path).into_diagnostic()?;

    let pass: Box<[u8]> = URL_SAFE_NO_PAD
        .decode(pass.trim().as_bytes())
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to decode password from {}", path.display()))?
        .into();

    Ok(pass)
}

#[tracing::instrument(err)]
fn main() -> Result<()> {
    // set panic hook to pretty print with miette's formatter
    miette::set_panic_hook();

    // parse cli arguments
    let mut args = cli::Opts::parse();

    // configure logger
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .without_time()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(args.verbosity.tracing_level_filter().into())
                .from_env_lossy(),
        )
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .into_diagnostic()
        .wrap_err("failed to set global tracing subscriber")?;

    debug!("{args:#?}");

    let config = match args.config_or_command.take() {
        // process subcommand
        (None, Some(cmd)) => return cmd.process(&args),
        (Some(path), None) => {
            let mut config = config::Config::load(&path)?;
            if let Err(err) = config.verify() {
                error!("failed to verify configuration: {err}");
            }
            config
        }
        (None, None) | (Some(_), Some(_)) => unreachable!(
            "bad state, one of config or subcommand should be available (clap should enforce this)"
        ),
    };

    debug!("{config:#?}");

    // Initialize state
    let state = AppState::from_args(&args, &config)?;

    info!("checking environment");

    // Load password hash
    let password_hash = config
        .password
        .file
        .as_deref()
        .map(load_password)
        .transpose()
        .wrap_err("failed to load password hash")?;

    ensure!(
        password_hash.is_some() || args.insecure,
        "a password must be used"
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .into_diagnostic()
        .wrap_err("failed to start the tokio runtime")?;

    rt.block_on(async_main(state, config, password_hash))
        .wrap_err("failed to run main loop")
}

async fn start_http_server(
    state: AppState<'static>,
    config: Config,
    pass: Option<Box<[u8]>>,
) -> miette::Result<()> {
    let config::Server {
        address,
        ip_source,
        key_file: _,
        ..
    } = config.server;

    // Create router
    let app = Router::new().route("/update", get(update_handler::update_records));
    // if a password is provided, validate it
    let app = if let Some(pass) = pass {
        app.layer(auth::layer(
            Box::leak(pass),
            Box::leak(config.password.salt),
        ))
    } else {
        app
    }
    .layer(ip_source.into_extension())
    .with_state(state);

    // Start services
    info!("starting listener on {address}");
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .into_diagnostic()?;
    info!("listening on {address}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .into_diagnostic()
}

#[tracing::instrument(name = "main", err, skip_all)]
async fn async_main(
    state: AppState<'static>,
    config: Config,
    pass: Option<Box<[u8]>>,
) -> Result<()> {
    // Update DNS record with previous IPs (if available)
    restore_saved_state(&state, &config)
        .await
        .wrap_err("failed to restore saved state")?;

    // Create save data task
    let save_state = state::SaveDataTask::from_app_state(&state);
    let save_task = save_state.save_state_task();

    // Start HTTP server in the background
    let server = tokio::spawn(start_http_server(state, config, pass));
    let server_abort = server.abort_handle();

    // Wait for CTRL_C or the server
    let res = tokio::select! {
        // Cancel work if CTRL+C is received
        res = tokio::signal::ctrl_c() => {
            info!("CTRL+C received, shutting down.");

            // CTRL+C received stop http server
            info!("Stopping HTTP server");
            server_abort.abort();

            res.into_diagnostic()
        }

        // Wait for HTTP server to stop
        res = server => {
            warn!("HTTP server stopped unexpectedly");
            res.into_diagnostic().wrap_err("failed to join HTTP server task").flatten()
        }

        // uninhabited, never reached
        res = save_task => { res }
    };

    if let Err(err) = res {
        warn!("stopped unexpectedly: {err}");
    }

    // Cleanup resources
    info!("Saving server state");
    let save_data = tokio::spawn(async move { save_state.trigger_save().await });

    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            if let Err(err) = signal {
                warn!("signal handler returned an error: {err}");
            }

            warn!("received second CTRL+C signal, not waiting for save job");
            Ok(())
        }
        res = save_data => {
            res.into_diagnostic().wrap_err("failed to join save job").flatten()
        }
    }
}

/// Update DNS record with previous IPs (if available)
async fn restore_saved_state(state: &AppState<'static>, config: &Config) -> miette::Result<()> {
    let data = state.saved_data.read().await;

    let mut actions = nsupdate::Action::from_saved_data(&data, &config.records).peekable();

    if actions.peek().is_some() {
        match nsupdate::nsupdate(state.key_file, actions).await {
            Ok(status) => {
                if !status.success() {
                    error!("nsupdate failed: code {status}");
                    bail!("nsupdate returned with code {status}");
                }
            }
            Err(err) => {
                error!("Failed to update records with previous IP: {err}");
                return Err(err)
                    .into_diagnostic()
                    .wrap_err("failed to update records with previous IP");
            }
        }
    }

    Ok(())
}
