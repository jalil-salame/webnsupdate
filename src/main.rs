use std::{
    ffi::OsStr,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::Duration,
};

use axum::{extract::State, routing::get, Json, Router};
use axum_auth::AuthBasic;
use axum_client_ip::{SecureClientIp, SecureClientIpSource};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Parser, Subcommand};
use http::StatusCode;
use miette::{bail, ensure, Context, IntoDiagnostic, Result};
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info, level_filters::LevelFilter, trace, warn};
use tracing_subscriber::EnvFilter;

mod password;
mod records;

const DEFAULT_TTL: Duration = Duration::from_secs(60);
const DEFAULT_SALT: &str = "UpdateMyDNS";

#[derive(Debug, Parser)]
struct Opts {
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
    /// see: https://docs.rs/axum-client-ip/latest/axum_client_ip/enum.SecureClientIpSource.html
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

    /// Salt added to the password
    salt: &'a str,

    /// The IN A/AAAA records that should have their IPs updated
    records: &'a [&'a str],

    /// The TSIG key file
    key_file: Option<&'a Path>,

    /// The password hash
    password_hash: Option<&'a [u8]>,

    /// The file where the last IP is stored
    ip_file: &'a Path,
}

fn load_ip(path: &Path) -> Result<Option<IpAddr>> {
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

    Ok(Some(
        data.parse()
            .into_diagnostic()
            .wrap_err("failed to parse last ip address")?,
    ))
}

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
                .with_default_directive(LevelFilter::WARN.into())
                .from_env_lossy(),
        )
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .into_diagnostic()
        .wrap_err("setting global tracing subscriber")?;

    // process subcommand
    if let Some(cmd) = args.subcommand.take() {
        return cmd.process(&args);
    }

    let Opts {
        address: ip,
        port,
        password_file,
        data_dir,
        key_file,
        insecure,
        subcommand: _,
        records,
        salt,
        ttl,
        ip_source,
    } = args;

    info!("checking environment");

    // Set state
    let ttl = Duration::from_secs(ttl);

    // Use last registered IP address if available
    let ip_file = data_dir.join("last-ip");

    let state = AppState {
        ttl,
        salt: salt.leak(),
        // Load DNS records
        records: records::load_no_verify(&records)?,
        // Load keyfile
        key_file: key_file
            .map(|key_file| -> miette::Result<_> {
                let path = key_file.as_path();
                std::fs::File::open(path)
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!("{} is not readable by the current user", path.display())
                    })?;
                Ok(&*Box::leak(key_file.into_boxed_path()))
            })
            .transpose()?,
        // Load password hash
        password_hash: password_file
            .map(|path| -> miette::Result<_> {
                let pass = std::fs::read_to_string(path.as_path()).into_diagnostic()?;

                let pass: Box<[u8]> = URL_SAFE_NO_PAD
                    .decode(pass.trim().as_bytes())
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to decode password from {}", path.display()))?
                    .into();

                Ok(&*Box::leak(pass))
            })
            .transpose()?,
        ip_file: Box::leak(ip_file.into_boxed_path()),
    };

    ensure!(
        state.password_hash.is_some() || insecure,
        "a password must be used"
    );

    ensure!(
        state.key_file.is_some() || insecure,
        "a key file must be used"
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .into_diagnostic()
        .wrap_err("failed to start the tokio runtime")?;

    rt.block_on(async {
        // Load previous IP and update DNS record to point to it (if available)
        match load_ip(state.ip_file) {
            Ok(Some(ip)) => match nsupdate(ip, ttl, state.key_file, state.records).await {
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
            },
            Ok(None) => {
                info!("No previous IP address set");
            }
            Err(err) => {
                error!("Failed to load last ip address: {err}")
            }
        };

        // Start services
        let app = Router::new()
            .route("/update", get(update_records))
            .layer(ip_source.into_extension())
            .with_state(state);
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
}

#[tracing::instrument(skip(state, pass), level = "trace", ret(level = "info"))]
async fn update_records(
    State(state): State<AppState<'static>>,
    AuthBasic((username, pass)): AuthBasic,
    SecureClientIp(ip): SecureClientIp,
) -> axum::response::Result<&'static str> {
    let Some(pass) = pass else {
        return Err((StatusCode::UNAUTHORIZED, Json::from("no password provided")).into());
    };

    if let Some(stored_pass) = state.password_hash {
        let password = pass.trim().to_string();
        let pass_hash = password::hash_identity(&username, &password, state.salt);
        if pass_hash.as_ref() != stored_pass {
            warn!("rejected update");
            trace!(
                "mismatched hashes:\n{}\n{}",
                URL_SAFE_NO_PAD.encode(pass_hash.as_ref()),
                URL_SAFE_NO_PAD.encode(stored_pass),
            );
            return Err((StatusCode::UNAUTHORIZED, "invalid identity").into());
        }
    }

    info!("accepted update");
    match nsupdate(ip, state.ttl, state.key_file, state.records).await {
        Ok(status) if status.success() => {
            tokio::task::spawn_blocking(move || {
                if let Err(err) = std::fs::write(state.ip_file, format!("{ip}")) {
                    error!("Failed to update last IP: {err}");
                }
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

#[tracing::instrument(level = "trace", ret(level = "warn"))]
async fn nsupdate(
    ip: IpAddr,
    ttl: Duration,
    key_file: Option<&Path>,
    records: &[&str],
) -> std::io::Result<ExitStatus> {
    let mut cmd = tokio::process::Command::new("nsupdate");
    if let Some(key_file) = key_file {
        cmd.args([OsStr::new("-k"), key_file.as_os_str()]);
    }
    debug!("spawning new process");
    let mut child = cmd
        .stdin(Stdio::piped())
        .spawn()
        .inspect_err(|err| warn!("failed to spawn child: {err}"))?;
    let mut stdin = child.stdin.take().expect("stdin not present");
    debug!("sending update request");
    stdin
        .write_all(update_ns_records(ip, ttl, records).as_bytes())
        .await
        .inspect_err(|err| warn!("failed to write to the stdin of nsupdate: {err}"))?;
    debug!("closing stdin");
    stdin
        .shutdown()
        .await
        .inspect_err(|err| warn!("failed to close stdin to nsupdate: {err}"))?;
    debug!("waiting for nsupdate to exit");
    child
        .wait()
        .await
        .inspect_err(|err| warn!("failed to wait for child: {err}"))
}

fn update_ns_records(ip: IpAddr, ttl: Duration, records: &[&str]) -> String {
    use std::fmt::Write;
    let ttl_s: u64 = ttl.as_secs();

    let rec_type = match ip {
        IpAddr::V4(_) => "A",
        IpAddr::V6(_) => "AAAA",
    };
    let mut cmds = String::from("server 127.0.0.1\n");
    for &record in records {
        writeln!(cmds, "update delete {record} {ttl_s} IN {rec_type}").unwrap();
        writeln!(cmds, "update add    {record} {ttl_s} IN {rec_type} {ip}").unwrap();
    }
    writeln!(cmds, "send\nquit").unwrap();
    cmds
}

#[cfg(test)]
mod test {
    use insta::assert_snapshot;

    use crate::{update_ns_records, DEFAULT_TTL};

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    #[allow(non_snake_case)]
    fn expected_update_string_A() {
        assert_snapshot!(update_ns_records(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            DEFAULT_TTL,
            &["example.com.", "example.org.", "example.net."],
        ), @r###"
        server 127.0.0.1
        update delete example.com. 60 IN A
        update add    example.com. 60 IN A 127.0.0.1
        update delete example.org. 60 IN A
        update add    example.org. 60 IN A 127.0.0.1
        update delete example.net. 60 IN A
        update add    example.net. 60 IN A 127.0.0.1
        send
        quit
        "###);
    }

    #[test]
    #[allow(non_snake_case)]
    fn expected_update_string_AAAA() {
        assert_snapshot!(update_ns_records(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            DEFAULT_TTL,
            &["example.com.", "example.org.", "example.net."],
        ), @r###"
        server 127.0.0.1
        update delete example.com. 60 IN AAAA
        update add    example.com. 60 IN AAAA ::1
        update delete example.org. 60 IN AAAA
        update add    example.org. 60 IN AAAA ::1
        update delete example.net. 60 IN AAAA
        update add    example.net. 60 IN AAAA ::1
        send
        quit
        "###);
    }
}
