use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use axum::{
    extract::{Query, State},
    routing::get,
    Router,
};
use axum_client_ip::ClientIp;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Parser, Subcommand};
use clap_verbosity_flag::Verbosity;
use config::Config;
use http::StatusCode;
use miette::{bail, ensure, Context, IntoDiagnostic, Result};
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

mod auth;
mod config;
mod nsupdate;
mod password;
mod records;

const DEFAULT_TTL: Duration = Duration::from_secs(60);
const DEFAULT_SALT: &str = "UpdateMyDNS";

#[derive(Debug, Parser)]
struct Opts {
    #[command(flatten)]
    verbosity: Verbosity<clap_verbosity_flag::InfoLevel>,

    /// Data directory
    #[arg(long, env, default_value = ".")]
    data_dir: PathBuf,

    /// Allow not setting a password
    #[arg(long)]
    insecure: bool,

    #[clap(flatten)]
    config_or_command: ConfigOrCommand,
}

#[derive(clap::Args, Debug)]
#[group(multiple = false)]
struct ConfigOrCommand {
    /// Path to the configuration file
    #[arg(long, short)]
    config: Option<PathBuf>,

    #[clap(subcommand)]
    subcommand: Option<Cmd>,
}

impl ConfigOrCommand {
    pub fn take(&mut self) -> (Option<PathBuf>, Option<Cmd>) {
        (self.config.take(), self.subcommand.take())
    }
}

#[derive(Debug, Subcommand)]
enum Cmd {
    Mkpasswd(password::Mkpasswd),
    /// Verify the configuration file
    Verify {
        /// Path to the configuration file
        config: PathBuf,
    },
}

impl Cmd {
    pub fn process(self, args: &Opts) -> Result<()> {
        match self {
            Cmd::Mkpasswd(mkpasswd) => mkpasswd.process(args),
            Cmd::Verify { config } => config::Config::load(&config) // load config
                .and_then(Config::verified) // verify config
                .map(drop), // ignore config data
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

    /// The IP type for which to allow updates
    ip_type: config::IpType,
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
    fn from_args(args: &Opts, config: &config::Config) -> miette::Result<Self> {
        let Opts {
            verbosity: _,
            data_dir,
            insecure,
            config_or_command: _,
        } = args;

        let config::Records {
            ttl,
            records,
            client_id: _,
            router_domain: _,
            ip_source: _,
            ip_type,
            key_file,
        } = &config.records;

        // Use last registered IP address if available
        let ip_file = Box::leak(data_dir.join("last-ip.json").into_boxed_path());

        // Leak DNS records
        let records: &[&str] = &*Vec::leak(
            records
                .iter()
                .map(|record| &*Box::leak(record.clone()))
                .collect(),
        );

        let state = AppState {
            ttl: **ttl,
            records,
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
            ip_type: *ip_type,
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

#[derive(Clone, Copy, Debug)]
struct Ipv6Prefix {
    prefix: Ipv6Addr,
    length: u32,
}

impl std::fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { prefix, length } = self;
        write!(f, "{prefix}/{length}")
    }
}

impl std::str::FromStr for Ipv6Prefix {
    type Err = miette::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (addr, len) = s.split_once('/').wrap_err("missing `/` in ipv6 prefix")?;
        Ok(Self {
            prefix: addr
                .parse()
                .into_diagnostic()
                .wrap_err("invalid ipv6 address for ipv6 prefix")?,
            length: len
                .parse()
                .into_diagnostic()
                .wrap_err("invalid length for ipv6 prefix")?,
        })
    }
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

    let config = match args.config_or_command.take() {
        // process subcommand
        (None, Some(cmd)) => return cmd.process(&args),
        (Some(path), None) => {
            let config = config::Config::load(&path)?;
            if let Err(err) = config.verify() {
                error!("failed to verify configuration: {err}");
            }
            config
        }
        (None, None) | (Some(_), Some(_)) => unreachable!(
            "bad state, one of config or subcommand should be available (clap should enforce this)"
        ),
    };

    // Initialize state
    let state = AppState::from_args(&args, &config)?;

    let Opts {
        verbosity: _,
        data_dir: _,
        insecure,
        config_or_command: _,
    } = args;

    info!("checking environment");

    // Load password hash
    let password_hash = config
        .password
        .password_file
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

        let mut actions = ips
            .ips()
            .filter(|ip| config.records.ip_type.valid_for_type(*ip))
            .flat_map(|ip| nsupdate::Action::from_records(ip, state.ttl, state.records))
            .peekable();

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

        // Create services
        let app = Router::new().route("/update", get(update_records));
        // if a password is provided, validate it
        let app = if let Some(pass) = password_hash {
            app.layer(auth::layer(
                Box::leak(pass),
                Box::leak(config.password.salt),
            ))
        } else {
            app
        }
        .layer(config.records.ip_source.into_extension())
        .with_state(state);

        let config::Server { address } = config.server;

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
    })
    .wrap_err("failed to run main loop")
}

/// Serde deserialization decorator to map empty Strings to None,
///
/// Adapted from: <https://github.com/tokio-rs/axum/blob/main/examples/query-params-with-empty-strings/src/main.rs>
fn empty_string_as_none<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    use serde::Deserialize;

    let opt = Option::<std::borrow::Cow<'de, str>>::deserialize(de)?;
    match opt.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => s.parse::<T>().map_err(serde::de::Error::custom).map(Some),
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FritzBoxUpdateParams {
    /// The domain that should be updated
    #[allow(unused)]
    #[serde(default, deserialize_with = "empty_string_as_none")]
    domain: Option<String>,
    /// IPv4 address for the domain
    #[serde(default, deserialize_with = "empty_string_as_none")]
    ipv4: Option<Ipv4Addr>,
    /// IPv6 address for the domain
    #[serde(default, deserialize_with = "empty_string_as_none")]
    ipv6: Option<Ipv6Addr>,
    /// IPv6 prefix for the home network
    #[allow(unused)]
    #[serde(default, deserialize_with = "empty_string_as_none")]
    ipv6prefix: Option<Ipv6Prefix>,
    /// Whether the networks uses both IPv4 and IPv6
    #[allow(unused)]
    #[serde(default, deserialize_with = "empty_string_as_none")]
    dualstack: Option<String>,
}

impl FritzBoxUpdateParams {
    fn has_data(&self) -> bool {
        let Self {
            domain,
            ipv4,
            ipv6,
            ipv6prefix,
            dualstack,
        } = self;
        domain.is_some()
            | ipv4.is_some()
            | ipv6.is_some()
            | ipv6prefix.is_some()
            | dualstack.is_some()
    }
}

#[tracing::instrument(skip(state), level = "trace", ret(level = "info"))]
async fn update_records(
    State(state): State<AppState<'static>>,
    ClientIp(ip): ClientIp,
    Query(update_params): Query<FritzBoxUpdateParams>,
) -> axum::response::Result<&'static str> {
    info!("accepted update from {ip}");

    if !update_params.has_data() {
        if !state.ip_type.valid_for_type(ip) {
            tracing::warn!(
                "rejecting update from {ip} as we are running a {} filter",
                state.ip_type
            );
            return Err((
                StatusCode::CONFLICT,
                format!("running in {} mode", state.ip_type),
            )
                .into());
        }

        return trigger_update(ip, &state).await;
    }

    // FIXME: mark suspicious updates (where IP doesn't match the update_ip) and reject them based
    // on policy

    let FritzBoxUpdateParams {
        domain: _,
        ipv4,
        ipv6,
        ipv6prefix: _,
        dualstack: _,
    } = update_params;

    if ipv4.is_none() && ipv6.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "failed to provide an IP for the update",
        )
            .into());
    }

    if let Some(ip) = ipv4 {
        let ip = IpAddr::V4(ip);
        if state.ip_type.valid_for_type(ip) {
            _ = trigger_update(ip, &state).await?;
        } else {
            tracing::warn!("requested update of IPv4 but we are {}", state.ip_type);
        }
    }

    if let Some(ip) = ipv6 {
        let ip = IpAddr::V6(ip);
        if state.ip_type.valid_for_type(ip) {
            _ = trigger_update(ip, &state).await?;
        } else {
            tracing::warn!("requested update of IPv6 but we are {}", state.ip_type);
        }
    }

    Ok("Successfully updated IP of records!\n")
}

#[tracing::instrument(skip(state), level = "trace", ret(level = "info"))]
async fn trigger_update(
    ip: IpAddr,
    state: &AppState<'static>,
) -> axum::response::Result<&'static str> {
    let actions = nsupdate::Action::from_records(ip, state.ttl, state.records);

    if actions.len() == 0 {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Nothing to do (e.g. we are ipv4-only but an ipv6 update was requested)",
        )
            .into());
    }

    match nsupdate::nsupdate(state.key_file, actions).await {
        Ok(status) if status.success() => {
            let ips = {
                // Update state
                let mut ips = state.last_ips.lock().await;
                ips.update(ip);
                ips.clone()
            };

            let ip_file = state.ip_file;
            tokio::task::spawn_blocking(move || {
                info!("updating last ips to {ips:?}");
                let data = serde_json::to_vec(&ips).expect("invalid serialization impl");
                if let Err(err) = std::fs::write(ip_file, data) {
                    error!("Failed to update last IP: {err}");
                }
                info!("updated last ips to {ips:?}");
            });

            Ok("Successfully updated IP of records!\n")
        }
        Ok(status) => {
            error!("nsupdate failed with code {status}");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "nsupdate failed, check server logs\n",
            )
                .into())
        }
        Err(error) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to update records: {error}\n"),
        )
            .into()),
    }
}

#[cfg(test)]
mod parse_query_params {
    use axum::extract::Query;

    use super::FritzBoxUpdateParams;

    #[test]
    fn no_params() {
        let uri = http::Uri::builder()
            .path_and_query("/update")
            .build()
            .unwrap();
        let query: Query<FritzBoxUpdateParams> = Query::try_from_uri(&uri).unwrap();
        insta::assert_debug_snapshot!(query, @r#"
    Query(
        FritzBoxUpdateParams {
            domain: None,
            ipv4: None,
            ipv6: None,
            ipv6prefix: None,
            dualstack: None,
        },
    )
    "#);
    }

    #[test]
    fn ipv4() {
        let uri = http::Uri::builder()
            .path_and_query("/update?ipv4=1.2.3.4")
            .build()
            .unwrap();
        let query: Query<FritzBoxUpdateParams> = Query::try_from_uri(&uri).unwrap();
        insta::assert_debug_snapshot!(query, @r#"
    Query(
        FritzBoxUpdateParams {
            domain: None,
            ipv4: Some(
                1.2.3.4,
            ),
            ipv6: None,
            ipv6prefix: None,
            dualstack: None,
        },
    )
    "#);
    }

    #[test]
    fn ipv6() {
        let uri = http::Uri::builder()
            .path_and_query("/update?ipv6=%3A%3A1234")
            .build()
            .unwrap();
        let query: Query<FritzBoxUpdateParams> = Query::try_from_uri(&uri).unwrap();
        insta::assert_debug_snapshot!(query, @r#"
    Query(
        FritzBoxUpdateParams {
            domain: None,
            ipv4: None,
            ipv6: Some(
                ::1234,
            ),
            ipv6prefix: None,
            dualstack: None,
        },
    )
    "#);
    }

    #[test]
    fn ipv4_and_ipv6() {
        let uri = http::Uri::builder()
            .path_and_query("/update?ipv4=1.2.3.4&ipv6=%3A%3A1234")
            .build()
            .unwrap();
        let query: Query<FritzBoxUpdateParams> = Query::try_from_uri(&uri).unwrap();
        insta::assert_debug_snapshot!(query, @r#"
    Query(
        FritzBoxUpdateParams {
            domain: None,
            ipv4: Some(
                1.2.3.4,
            ),
            ipv6: Some(
                ::1234,
            ),
            ipv6prefix: None,
            dualstack: None,
        },
    )
    "#);
    }

    #[test]
    fn ipv4_and_empty_ipv6() {
        let uri = http::Uri::builder()
            .path_and_query("/update?ipv4=1.2.3.4&ipv6=")
            .build()
            .unwrap();
        let query: Query<FritzBoxUpdateParams> = Query::try_from_uri(&uri).unwrap();
        insta::assert_debug_snapshot!(query, @r#"
    Query(
        FritzBoxUpdateParams {
            domain: None,
            ipv4: Some(
                1.2.3.4,
            ),
            ipv6: None,
            ipv6prefix: None,
            dualstack: None,
        },
    )
    "#);
    }

    #[test]
    fn empty_ipv4_and_ipv6() {
        let uri = http::Uri::builder()
            .path_and_query("/update?ipv4=&ipv6=%3A%3A1234")
            .build()
            .unwrap();
        let query: Query<FritzBoxUpdateParams> = Query::try_from_uri(&uri).unwrap();
        insta::assert_debug_snapshot!(query, @r#"
    Query(
        FritzBoxUpdateParams {
            domain: None,
            ipv4: None,
            ipv6: Some(
                ::1234,
            ),
            ipv6prefix: None,
            dualstack: None,
        },
    )
    "#);
    }
}
