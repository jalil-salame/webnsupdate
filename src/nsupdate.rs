use std::ffi::OsStr;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::path::Path;
use std::process::ExitStatus;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tracing::debug;
use tracing::warn;

use crate::config::Record;
use crate::config::Records;
use crate::state::SavedData;
use crate::state::SavedIps;

pub enum Action<'a> {
    // Reassign a domain to a different IP
    Reassign {
        domain: &'a str,
        to: IpAddr,
        ttl: Duration,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct IpPair {
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
}

impl IpPair {
    pub fn new(ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) -> Self {
        Self { ipv4, ipv6 }
    }

    pub fn is_empty(self) -> bool {
        self.ipv4.is_none() & self.ipv6.is_none()
    }

    pub fn add_if_missing(self, ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ipv4) if self.ipv4.is_none() => Self {
                ipv4: Some(ipv4),
                ..self
            },
            IpAddr::V6(ipv6) if self.ipv6.is_none() => Self {
                ipv6: Some(ipv6),
                ..self
            },
            IpAddr::V4(_) | IpAddr::V6(_) => self,
        }
    }

    pub fn ips(self) -> impl Iterator<Item = IpAddr> {
        self.ipv4
            .map(IpAddr::V4)
            .into_iter()
            .chain(self.ipv6.map(IpAddr::V6))
    }
}

impl From<IpAddr> for IpPair {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(ipv4_addr) => Self {
                ipv4: Some(ipv4_addr),
                ipv6: None,
            },
            IpAddr::V6(ipv6_addr) => Self {
                ipv4: None,
                ipv6: Some(ipv6_addr),
            },
        }
    }
}

impl From<SavedIps> for IpPair {
    fn from(SavedIps { ipv4, ipv6 }: SavedIps) -> Self {
        IpPair { ipv4, ipv6 }
    }
}

impl<'a> Action<'a> {
    pub fn from_saved_data<'b>(
        saved: &'b SavedData,
        records: &'a Records,
    ) -> impl Iterator<Item = Self> + use<'a, 'b> {
        records
            .iter()
            .filter_map(|(domain, record)| {
                Some((
                    domain,
                    record,
                    saved.get(domain).cloned().map(IpPair::from)?,
                ))
            })
            .flat_map(Self::from_record_tuple)
    }

    /// Create a set of [`Action`]s reassigning the domains in `records` to the
    /// specified [`IpAddr`]
    pub fn from_record(
        domain: &'a str,
        record: &'a Record,
        ips: IpPair,
    ) -> impl Iterator<Item = Self> {
        std::iter::once(domain)
            .chain(record.router_domain.as_deref())
            .flat_map(move |domain| {
                ips.ips()
                    .filter(|&ip| record.ip_type.valid_for_type(ip))
                    .map(|to| Self::Reassign {
                        domain,
                        to,
                        ttl: *record.ttl,
                    })
            })
    }

    fn from_record_tuple(
        (domain, record, ips): (&'a str, &'a Record, IpPair),
    ) -> impl Iterator<Item = Self> {
        Self::from_record(domain, record, ips)
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
    use crate::nsupdate::IpPair;

    #[test]
    fn expected_update_string_ipv4() {
        let mut buf = Vec::new();
        let record = crate::config::Record::new();
        let actions = Action::from_record(
            "example.com.",
            &record,
            IpPair::from(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        );
        update_ns_records(&mut buf, actions).unwrap();

        assert_snapshot!(String::from_utf8(buf).unwrap(), @r###"
        server 127.0.0.1
        update delete example.com. 60 IN A
        update add    example.com. 60 IN A 127.0.0.1
        send
        quit
        "###);
    }

    #[test]
    fn expected_update_string_ipv6() {
        let mut buf = Vec::new();
        let record = crate::config::Record::new();
        let actions = Action::from_record(
            "example.com.",
            &record,
            IpPair::from(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        );
        update_ns_records(&mut buf, actions).unwrap();

        assert_snapshot!(String::from_utf8(buf).unwrap(), @r###"
        server 127.0.0.1
        update delete example.com. 60 IN AAAA
        update add    example.com. 60 IN AAAA ::1
        send
        quit
        "###);
    }

    #[test]
    fn expected_update_string_both() {
        let mut buf = Vec::new();
        let record = crate::config::Record::new();
        let actions = Action::from_record(
            "example.com.",
            &record,
            IpPair {
                ipv4: Some(Ipv4Addr::LOCALHOST),
                ipv6: Some(Ipv6Addr::LOCALHOST),
            },
        );
        update_ns_records(&mut buf, actions).unwrap();

        assert_snapshot!(String::from_utf8(buf).unwrap(), @r###"
        server 127.0.0.1
        update delete example.com. 60 IN A
        update add    example.com. 60 IN A 127.0.0.1
        update delete example.com. 60 IN AAAA
        update add    example.com. 60 IN AAAA ::1
        send
        quit
        "###);
    }
}
