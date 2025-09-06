use std::ffi::OsStr;
use std::net::IpAddr;
use std::path::Path;
use std::process::ExitStatus;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tracing::debug;
use tracing::warn;

pub enum Action<'a> {
    // Reassign a domain to a different IP
    Reassign {
        domain: &'a str,
        to: IpAddr,
        ttl: Duration,
    },
}

impl<'a> Action<'a> {
    /// Create a set of [`Action`]s reassigning the domains in `records` to the
    /// specified [`IpAddr`]
    pub fn from_records(
        to: IpAddr,
        ttl: Duration,
        records: &'a [&'a str],
    ) -> impl IntoIterator<Item = Self> + std::iter::ExactSizeIterator + 'a {
        records
            .iter()
            .map(move |&domain| Action::Reassign { domain, to, ttl })
    }
}

impl std::fmt::Display for Action<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Reassign { domain, to, ttl } => {
                let ttl = ttl.as_secs();
                let kind = match to {
                    IpAddr::V4(_) => "A",
                    IpAddr::V6(_) => "AAAA",
                };
                // Delete previous record of type `kind`
                writeln!(f, "update delete {domain} {ttl} IN {kind}")?;
                // Add record with new IP
                writeln!(f, "update add    {domain} {ttl} IN {kind} {to}")
            }
        }
    }
}

#[tracing::instrument(level = "trace", skip(actions), ret(level = "warn"))]
pub async fn nsupdate(
    key_file: Option<&Path>,
    actions: impl IntoIterator<Item = Action<'_>>,
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
    let mut buf = Vec::new();
    update_ns_records(&mut buf, actions).unwrap();
    stdin
        .write_all(&buf)
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

fn update_ns_records<'a>(
    mut buf: impl std::io::Write,
    actions: impl IntoIterator<Item = Action<'a>>,
) -> std::io::Result<()> {
    writeln!(buf, "server 127.0.0.1")?;
    for action in actions {
        write!(buf, "{action}")?;
    }
    writeln!(buf, "send")?;
    writeln!(buf, "quit")
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;

    use insta::assert_snapshot;

    use super::Action;
    use super::update_ns_records;
    use crate::DEFAULT_TTL;

    #[test]
    #[expect(non_snake_case, reason = "I can't tell that aaaa means AAAA record")]
    fn expected_update_string_A() {
        let mut buf = Vec::new();
        let actions = Action::from_records(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            DEFAULT_TTL,
            &["example.com.", "example.org.", "example.net."],
        );
        update_ns_records(&mut buf, actions).unwrap();

        assert_snapshot!(String::from_utf8(buf).unwrap(), @r###"
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
    #[expect(non_snake_case, reason = "I can't tell that aaaa means AAAA record")]
    fn expected_update_string_AAAA() {
        let mut buf = Vec::new();
        let actions = Action::from_records(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            DEFAULT_TTL,
            &["example.com.", "example.org.", "example.net."],
        );
        update_ns_records(&mut buf, actions).unwrap();

        assert_snapshot!(String::from_utf8(buf).unwrap(), @r###"
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
