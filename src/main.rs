use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use axum::{extract::State, routing::get, Router};
use axum_client_ip::{SecureClientIp, SecureClientIpSource};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Parser, Subcommand};
use clap_verbosity_flag::Verbosity;
use http::StatusCode;
use miette::{bail, ensure, Context, IntoDiagnostic, Result};
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

mod auth;
mod nsupdate;
mod password;
mod records;

const DEFAULT_TTL: Duration = Duration::from_secs(60);
const DEFAULT_SALT: &str = "UpdateMyDNS";

#[derive(Debug, Parser)]
struct Opts {
    #[command(flatten)]
    verbosity: Verbosity<clap_verbosity_flag::InfoLevel>,

    /// Ip address of the server
    #[arg(long, default_value = "127.0.0.1")]
    address: IpAddr,

    /// Port of the server
    #[arg(long, default_value_t = 5353)]
    port: u16,

    /// File containing password to match against
    ///
    /// Should be of the format `username:password` and contain a single password
    #[arg(long)]
    password_file: Option<PathBuf>,

    /// Salt to get more unique hashed passwords and prevent table based attacks
    #[arg(long, default_value = DEFAULT_SALT)]
    salt: String,

    /// Time To Live (in seconds) to set on the DNS records
    #[arg(long, default_value_t = DEFAULT_TTL.as_secs())]
    ttl: u64,

    /// Data directory
    #[arg(long, default_value = ".")]
    data_dir: PathBuf,

    /// File containing the records that should be updated when an update request is made
    ///
    /// There should be one record per line:
    ///
    /// ```text
    /// example.com.
    /// mail.example.com.
    /// ```
    #[arg(long)]
    records: PathBuf,

    /// Keyfile `nsupdate` should use
    ///
    /// If specified, then `webnsupdate` must have read access to the file
    #[arg(long)]
    key_file: Option<PathBuf>,

    /// Allow not setting a password
    #[arg(long)]
    insecure: bool,

    /// Set client IP source
    ///
    /// see: <https://docs.rs/axum-client-ip/latest/axum_client_ip/enum.SecureClientIpSource.html>
    #[clap(long, default_value = "RightmostXForwardedFor")]
    ip_source: SecureClientIpSource,

    #[clap(subcommand)]
    subcommand: Option<Cmd>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    Mkpasswd(password::Mkpasswd),
    /// Verify the records file
    Verify,
}

impl Cmd {
    pub fn process(self, args: &Opts) -> Result<()> {
        match self {
            Cmd::Mkpasswd(mkpasswd) => mkpasswd.process(args),
            Cmd::Verify => records::load(&args.records).map(drop),
        }
    }
}

#[derive(Clone)]
struct AppState<'a> {
    /// TTL set on the Zonefile
    ttl: Duration,

    /// The IN A/AAAA records that should have their IPs updated
    records: &'a [&'a str],

    /// The TSIG key file
    key_file: Option<&'a Path>,

    /// The file where the last IP is stored
    ip_file: &'a Path,

    /// Last recorded IPs
    last_ips: std::sync::Arc<tokio::sync::Mutex<SavedIPs>>,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
struct SavedIPs {
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv4: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv6: Option<Ipv6Addr>,
}

impl SavedIPs {
    fn update(&mut self, ip: IpAddr) {
        match ip {
            IpAddr::V4(ipv4_addr) => self.ipv4 = Some(ipv4_addr),
            IpAddr::V6(ipv6_addr) => self.ipv6 = Some(ipv6_addr),
        }
    }

    fn ips(&self) -> impl Iterator<Item = IpAddr> {
        self.ipv4
            .map(IpAddr::V4)
            .into_iter()
            .chain(self.ipv6.map(IpAddr::V6))
    }

    fn from_str(data: &str) -> miette::Result<Self> {
        match data.parse::<IpAddr>() {
            // Old format
            Ok(IpAddr::V4(ipv4)) => Ok(Self {
                ipv4: Some(ipv4),
                ipv6: None,
            }),
            Ok(IpAddr::V6(ipv6)) => Ok(Self {
                ipv4: None,
                ipv6: Some(ipv6),
            }),
            Err(_) => serde_json::from_str(data).into_diagnostic(),
        }
    }
}

impl AppState<'static> {
    fn from_args(args: &Opts) -> miette::Result<Self> {
        let Opts {
            verbosity: _,
            address: _,
            port: _,
            password_file: _,
            data_dir,
            key_file,
            insecure,
            subcommand: _,
            records,
            salt: _,
            ttl,
            ip_source: _,
        } = args;

        // Set state
        let ttl = Duration::from_secs(*ttl);

        // Use last registered IP address if available
        let ip_file = Box::leak(data_dir.join("last-ip").into_boxed_path());

        let state = AppState {
            ttl,
            // Load DNS records
            records: records::load_no_verify(records)?,
            // Load keyfile
            key_file: key_file
                .as_deref()
                .map(|path| -> miette::Result<_> {
                    std::fs::File::open(path)
                        .into_diagnostic()
                        .wrap_err_with(|| {
                            format!("{} is not readable by the current user", path.display())
                        })?;
                    Ok(&*Box::leak(path.into()))
                })
                .transpose()?,
            ip_file,
            last_ips: std::sync::Arc::new(tokio::sync::Mutex::new(
                load_ip(ip_file)?.unwrap_or_default(),
            )),
        };

        ensure!(
            state.key_file.is_some() || *insecure,
            "a key file must be used"
        );

        Ok(state)
    }
}

fn load_ip(path: &Path) -> Result<Option<SavedIPs>> {
    debug!("loading last IP from {}", path.display());
    let data = match std::fs::read_to_string(path) {
        Ok(ip) => ip,
        Err(err) => {
            return match err.kind() {
                ErrorKind::NotFound => Ok(None),
                _ => Err(err).into_diagnostic().wrap_err_with(|| {
                    format!("failed to load last ip address from {}", path.display())
                }),
            }
        }
    };

    SavedIPs::from_str(&data)
        .wrap_err_with(|| format!("failed to load last ip address from {}", path.display()))
        .map(Some)
}

#[tracing::instrument(err)]
fn main() -> Result<()> {
    // set panic hook to pretty print with miette's formatter
    miette::set_panic_hook();

    // parse cli arguments
    let mut args = Opts::parse();

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

    debug!("{args:?}");

    // process subcommand
    if let Some(cmd) = args.subcommand.take() {
        return cmd.process(&args);
    }

    // Initialize state
    let state = AppState::from_args(&args)?;

    let Opts {
        verbosity: _,
        address: ip,
        port,
        password_file,
        data_dir: _,
        key_file: _,
        insecure,
        subcommand: _,
        records: _,
        salt,
        ttl: _,
        ip_source,
    } = args;

    info!("checking environment");

    // Load password hash
    let password_hash = password_file
        .map(|path| -> miette::Result<_> {
            let path = path.as_path();
            let pass = std::fs::read_to_string(path).into_diagnostic()?;

            let pass: Box<[u8]> = URL_SAFE_NO_PAD
                .decode(pass.trim().as_bytes())
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to decode password from {}", path.display()))?
                .into();

            Ok(pass)
        })
        .transpose()
        .wrap_err("failed to load password hash")?;

    ensure!(
        password_hash.is_some() || insecure,
        "a password must be used"
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .into_diagnostic()
        .wrap_err("failed to start the tokio runtime")?;

    rt.block_on(async {
        // Update DNS record with previous IPs (if available)
        let ips = state.last_ips.lock().await.clone();
        for ip in ips.ips() {
            match nsupdate::nsupdate(ip, state.ttl, state.key_file, state.records).await {
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

        // Create services
        let app = Router::new().route("/update", get(update_records));
        // if a password is provided, validate it
        let app = if let Some(pass) = password_hash {
            app.layer(auth::layer(Box::leak(pass), String::leak(salt)))
        } else {
            app
        }
        .layer(ip_source.into_extension())
        .with_state(state);

        // Start services
        info!("starting listener on {ip}:{port}");
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(ip, port))
            .await
            .into_diagnostic()?;
        info!("listening on {ip}:{port}");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .into_diagnostic()
    })
    .wrap_err("failed to run main loop")
}

#[tracing::instrument(skip(state), level = "trace", ret(level = "info"))]
async fn update_records(
    State(state): State<AppState<'static>>,
    SecureClientIp(ip): SecureClientIp,
) -> axum::response::Result<&'static str> {
    info!("accepted update from {ip}");
    match nsupdate::nsupdate(ip, state.ttl, state.key_file, state.records).await {
        Ok(status) if status.success() => {
            let ips = {
                // Update state
                let mut ips = state.last_ips.lock().await;
                ips.update(ip);
                ips.clone()
            };

            tokio::task::spawn_blocking(move || {
                info!("updating last ips to {ips:?}");
                let data = serde_json::to_vec(&ips).expect("invalid serialization impl");
                if let Err(err) = std::fs::write(state.ip_file, data) {
                    error!("Failed to update last IP: {err}");
                }
                info!("updated last ips to {ips:?}");
            });

            Ok("successful update")
        }
        Ok(status) => {
            error!("nsupdate failed with code {status}");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "nsupdate failed, check server logs",
            )
                .into())
        }
        Err(error) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to update records: {error}"),
        )
            .into()),
    }
}
