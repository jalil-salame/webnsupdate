use std::{
    ffi::OsStr,
    io::Write,
    net::{IpAddr, SocketAddr},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::Duration,
};

use axum::{extract::State, routing::get, Json, Router};
use axum_auth::AuthBasic;
use axum_client_ip::{SecureClientIp, SecureClientIpSource};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Args, Parser, Subcommand};
use http::StatusCode;
use miette::{ensure, miette, Context, IntoDiagnostic, LabeledSpan, NamedSource, Result};
use ring::digest::Digest;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info, level_filters::LevelFilter, trace, warn};
use tracing_subscriber::EnvFilter;

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

#[derive(Debug, Args)]
struct Mkpasswd {
    /// The username
    username: String,
    /// The password
    password: String,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Create a password file
    ///
    /// If `--password-file` is provided, the password is written to that file
    Mkpasswd(Mkpasswd),
    /// Verify the records file
    Verify,
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
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    miette::set_panic_hook();
    let Opts {
        address: ip,
        port,
        password_file,
        key_file,
        insecure,
        subcommand,
        records,
        salt,
        ttl,
        ip_source,
    } = Opts::parse();
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
    match subcommand {
        Some(Cmd::Mkpasswd(args)) => return mkpasswd(args, password_file.as_deref(), &salt),
        Some(Cmd::Verify) => {
            let data = std::fs::read_to_string(&records)
                .into_diagnostic()
                .wrap_err_with(|| format!("trying to read {}", records.display()))?;
            return verify_records(&data, &records);
        }
        None => {}
    }
    info!("checking environment");
    // Set state
    let ttl = Duration::from_secs(ttl);
    let mut state = AppState {
        ttl,
        salt: salt.leak(),
        records: &[],
        key_file: None,
        password_hash: None,
    };
    if let Some(path) = password_file {
        let pass = std::fs::read_to_string(&path).into_diagnostic()?;

        let pass: Box<[u8]> = URL_SAFE_NO_PAD
            .decode(pass.trim().as_bytes())
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to decode password from {}", path.display()))?
            .into();
        state.password_hash = Some(Box::leak(pass));
    } else {
        ensure!(insecure, "a password must be used");
    }
    if let Some(key_file) = key_file {
        let path = key_file.as_path();
        std::fs::File::open(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("{} is not readable by the current user", path.display()))?;
        state.key_file = Some(Box::leak(key_file.into_boxed_path()));
    } else {
        ensure!(insecure, "a key file must be used");
    }
    let data = std::fs::read_to_string(&records)
        .into_diagnostic()
        .wrap_err_with(|| format!("loading records from {}", records.display()))?;
    if let Err(err) = verify_records(&data, &records) {
        warn!("invalid records found: {err}");
    }
    state.records = data
        .lines()
        .map(|s| &*s.to_string().leak())
        .collect::<Vec<&'static str>>()
        .leak();
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
        let pass_hash = hash_identity(&username, &password, state.salt);
        if pass_hash.as_ref() != stored_pass {
            warn!("rejected update");
            trace!(
                "mismatched hashes:\n{}\n{}",
                URL_SAFE_NO_PAD.encode(pass_hash.as_ref()),
                URL_SAFE_NO_PAD.encode(stored_pass.as_ref()),
            );
            return Err((StatusCode::UNAUTHORIZED, "invalid identity").into());
        }
    }
    info!("accepted update");
    match nsupdate(ip, state.ttl, state.key_file, state.records).await {
        Ok(status) => {
            if status.success() {
                Ok("successful update")
            } else {
                error!("nsupdate failed");
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "nsupdate failed, check server logs",
                )
                    .into())
            }
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

fn hash_identity(username: &str, password: &str, salt: &str) -> Digest {
    let mut data = Vec::with_capacity(username.len() + password.len() + salt.len() + 1);
    write!(data, "{username}:{password}{salt}").unwrap();
    ring::digest::digest(&ring::digest::SHA256, &data)
}

fn mkpasswd(
    Mkpasswd { username, password }: Mkpasswd,
    password_file: Option<&Path>,
    salt: &str,
) -> miette::Result<()> {
    let hash = hash_identity(&username, &password, salt);
    let encoded = URL_SAFE_NO_PAD.encode(hash.as_ref());
    let Some(path) = password_file else {
        println!("{encoded}");
        return Ok(());
    };
    let err = || format!("trying to save password hash to {}", path.display());
    std::fs::File::options()
        .mode(0o600)
        .create_new(true)
        .open(path)
        .into_diagnostic()
        .wrap_err_with(err)?
        .write_all(encoded.as_bytes())
        .into_diagnostic()
        .wrap_err_with(err)?;

    Ok(())
}

fn verify_records(data: &str, path: &Path) -> miette::Result<()> {
    let source = || NamedSource::new(path.display().to_string(), data.to_string());
    let mut byte_offset = 0usize;
    for line in data.lines() {
        if line.is_empty() {
            continue;
        }
        ensure!(
            line.len() <= 255,
            miette!(
                labels = [LabeledSpan::new(
                    Some("this line".to_string()),
                    byte_offset,
                    line.len(),
                )],
                help = "fully qualified domain names can be at most 255 characters long",
                url = "https://en.wikipedia.org/wiki/Fully_qualified_domain_name",
                "hostname too long ({} octets)",
                line.len(),
            )
            .with_source_code(source())
        );
        ensure!(
            line.ends_with('.'),
            miette!(
                labels = [LabeledSpan::new(
                    Some("last character".to_string()),
                    byte_offset + line.len() - 1,
                    1,
                )],
                help = "hostname should be a fully qualified domain name (end with a '.')",
                url = "https://en.wikipedia.org/wiki/Fully_qualified_domain_name",
                "not a fully qualified domain name"
            )
            .with_source_code(source())
        );
        let mut local_offset = 0usize;
        for label in line.strip_suffix('.').unwrap_or(line).split('.') {
            ensure!(
                !label.is_empty(),
                miette!(
                    labels = [LabeledSpan::new(
                        Some("label".to_string()),
                        byte_offset + local_offset,
                        label.len(),
                    )],
                    help = "each label should have at least one character",
                    url = "https://en.wikipedia.org/wiki/Fully_qualified_domain_name",
                    "empty label",
                )
                .with_source_code(source())
            );
            ensure!(
                label.len() <= 63,
                miette!(
                    labels = [LabeledSpan::new(
                        Some("label".to_string()),
                        byte_offset + local_offset,
                        label.len(),
                    )],
                    help = "labels should be at most 63 octets",
                    url = "https://en.wikipedia.org/wiki/Fully_qualified_domain_name",
                    "label too long ({} octets)",
                    label.len(),
                )
                .with_source_code(source())
            );
            for (offset, octet) in label.bytes().enumerate() {
                ensure!(
                    octet.is_ascii(),
                    miette!(
                        labels = [LabeledSpan::new(
                            Some("octet".to_string()),
                            byte_offset + local_offset + offset,
                            1,
                        )],
                        help = "we only accept ascii characters",
                        url = "https://en.wikipedia.org/wiki/Hostname#Syntax",
                        "'{}' is not ascii",
                        octet.escape_ascii(),
                    )
                    .with_source_code(source())
                );
                ensure!(
                    octet.is_ascii_alphanumeric() || octet == b'-' || octet == b'_',
                    miette!(
                        labels = [LabeledSpan::new(
                            Some("octet".to_string()),
                            byte_offset + local_offset + offset,
                            1,
                        )],
                        help = "hostnames are only allowed to contain characters in [a-zA-Z0-9_-]",
                        url = "https://en.wikipedia.org/wiki/Hostname#Syntax",
                        "invalid octet: '{}'",
                        octet.escape_ascii(),
                    )
                    .with_source_code(source())
                );
            }
            local_offset += label.len() + 1;
        }
        byte_offset += line.len() + 1;
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use insta::assert_snapshot;

    use crate::{update_ns_records, verify_records, DEFAULT_TTL};

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

    #[test]
    fn valid_records() -> miette::Result<()> {
        verify_records(
            "\
            example.com.\n\
            example.org.\n\
            example.net.\n\
            subdomain.example.com.\n\
            ",
            std::path::Path::new("test_records_valid"),
        )
    }

    #[test]
    fn hostname_too_long() {
        let err = verify_records(
            "\
            example.com.\n\
            example.org.\n\
            example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.net.\n\
            subdomain.example.com.\n\
            ",
            std::path::Path::new("test_records_invalid"),
        )
        .unwrap_err();
        assert_snapshot!(err, @"hostname too long (260 octets)");
    }

    #[test]
    fn not_fqd() {
        let err = verify_records(
            "\
            example.com.\n\
            example.org.\n\
            example.net\n\
            subdomain.example.com.\n\
            ",
            std::path::Path::new("test_records_invalid"),
        )
        .unwrap_err();
        assert_snapshot!(err, @"not a fully qualified domain name");
    }

    #[test]
    fn empty_label() {
        let err = verify_records(
            "\
            example.com.\n\
            name..example.org.\n\
            example.net.\n\
            subdomain.example.com.\n\
            ",
            std::path::Path::new("test_records_invalid"),
        )
        .unwrap_err();
        assert_snapshot!(err, @"empty label");
    }

    #[test]
    fn label_too_long() {
        let err = verify_records(
            "\
            example.com.\n\
            name.an-entremely-long-label-that-should-not-exist-because-it-goes-against-the-spec.example.org.\n\
            example.net.\n\
            subdomain.example.com.\n\
            ",
            std::path::Path::new("test_records_invalid"),
        )
        .unwrap_err();
        assert_snapshot!(err, @"label too long (78 octets)");
    }

    #[test]
    fn invalid_ascii() {
        let err = verify_records(
            "\
            example.com.\n\
            name.this-is-not-aßcii.example.org.\n\
            example.net.\n\
            subdomain.example.com.\n\
            ",
            std::path::Path::new("test_records_invalid"),
        )
        .unwrap_err();
        assert_snapshot!(err, @r###"'\xc3' is not ascii"###);
    }

    #[test]
    fn invalid_octet() {
        let err = verify_records(
            "\
            example.com.\n\
            name.this-character:-is-not-allowed.example.org.\n\
            example.net.\n\
            subdomain.example.com.\n\
            ",
            std::path::Path::new("test_records_invalid"),
        )
        .unwrap_err();
        assert_snapshot!(err, @"invalid octet: ':'");
    }
}
