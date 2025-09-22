use std::ffi::OsStr;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::path::Path;
use std::process::ExitStatus;
use std::process::Stdio;
use std::time::Duration;

use miette::Diagnostic;
use tokio::io::AsyncWriteExt;
use tracing::debug;
use tracing::warn;

use crate::config::Record;
use crate::config::Records;
use crate::state::SavedData;
use crate::state::SavedIps;
use crate::update_handler::Ipv6Prefix;

pub struct RecordUpdate<'r> {
    /// The domain whose record to update
    pub domain: &'r str,
    /// The record configuration
    pub record: &'r Record,
    /// The new IPs for the record
    pub ips: IpPair,
    /// The IPv6 prefix of the network
    pub prefix: Option<Ipv6Prefix>,
}

impl<'r> RecordUpdate<'r> {
    /// Return the update [`Action`]s to take for this record update
    pub fn actions(
        &self,
        data: Option<&SavedIps>,
    ) -> Result<impl Iterator<Item = Action<'r>> + use<'r>, RecordUpdateError> {
        Ok(self
            .ipv4_action(data)
            .into_iter()
            .chain(self.ipv6_action(data)?)
            .chain(self.router_action(data)?))
    }

    pub fn save_data(&self, data: &mut SavedData) {
        data.update(self.domain, self.ips, self.prefix);
    }

    fn into_actions(
        self,
        data: Option<&SavedIps>,
    ) -> Result<impl Iterator<Item = Action<'r>>, RecordUpdateError> {
        self.actions(data)
    }

    // helper method
    fn action(&self, ip: impl Into<IpAddr>) -> Action<'r> {
        Action::Reassign {
            domain: self.domain,
            to: ip.into(),
            ttl: *self.record.ttl,
        }
    }

    #[must_use]
    fn needs_ipv4_update(&self, saved: &SavedIps) -> bool {
        match (self.ips.ipv4, saved.ipv4) {
            (None, None | Some(_)) => false,
            // no saved ipv4
            (Some(_), None) => true,
            // ipv4 changed
            (Some(update), Some(saved)) => update != saved,
        }
    }

    /// Action to update the domain's A record
    fn ipv4_action(&self, data: Option<&SavedIps>) -> Option<Action<'r>> {
        if !self.record.ip_type.accepts_ipv4() {
            return None;
        }

        // skip already updated
        if data.is_some_and(|saved| !self.needs_ipv4_update(saved)) {
            return None;
        }

        Some(self.action(self.ips.ipv4?))
    }

    #[must_use]
    fn needs_ipv6_update(&self, saved: &SavedIps) -> bool {
        match (self.ips.ipv6, saved.ipv6) {
            // no updated ipv6
            (None, None | Some(_)) => false,
            // no saved ipv6
            (Some(_), None) => true,
            // ipv6 changed
            (Some(update), Some(saved)) if update != saved => true,
            // same ipv6, check if ipv6prefix changed
            (Some(_), Some(_)) => match (self.prefix, saved.ipv6prefix) {
                (None, None | Some(_)) => false,
                // no saved ipv6prefix
                (Some(_), None) => true,
                // ipv6prefix changed
                (Some(update), Some(saved)) => update != saved,
            },
        }
    }

    /// Action to update the domain's AAAA record
    fn ipv6_action(
        &self,
        data: Option<&SavedIps>,
    ) -> Result<Option<Action<'r>>, RecordUpdateError> {
        if !self.record.ip_type.accepts_ipv6() {
            return Ok(None);
        }

        // skip already updated
        if data.is_some_and(|saved| !self.needs_ipv6_update(saved)) {
            return Ok(None);
        }

        RecordUpdateError::check_ip(self.ips.ipv6, self.record.client_id, self.prefix)
            .map(|ip| ip.map(|ip| self.action(ip)))
    }

    /// Action to update the Router's domain
    fn router_action(
        &self,
        data: Option<&SavedIps>,
    ) -> Result<Option<Action<'r>>, RecordUpdateError> {
        if !self.record.ip_type.accepts_ipv6() {
            return Ok(None);
        }

        // has ipv6 update
        let (Some(domain), Some(ip)) = (self.record.router_domain.as_deref(), self.ips.ipv6) else {
            return Ok(None);
        };

        if self.record.client_id.is_none() {
            return Err(RecordUpdateError::NoClientId);
        }

        // skip already updated
        if data.is_some_and(|saved| saved.ipv6.is_some_and(|saved| saved == ip)) {
            return Ok(None);
        }

        Ok(Some(Action::Reassign {
            domain,
            to: ip.into(),
            ttl: *self.record.ttl,
        }))
    }
}

#[derive(Debug, Diagnostic, thiserror::Error)]
pub enum RecordUpdateError {
    #[error("record had a configured client_id but no ipv6prefix was provided with the update")]
    NoIpv6Prefix,

    #[error("record had a configured router_domain but no client_id")]
    NoClientId,

    #[error(
        "update IPv6 is supposed to be the router's IP, but it was the same as the \
         prefix+client_id"
    )]
    #[diagnostic(help("router_ip={router_ip}, client_id={client_id} and prefix={prefix}"))]
    ClientIpSameAsUpdateIP {
        router_ip: Ipv6Addr,
        client_id: Ipv6Addr,
        prefix: Ipv6Prefix,
    },
}

impl RecordUpdateError {
    fn check_ip(
        router_ip: Option<Ipv6Addr>,
        client_id: Option<Ipv6Addr>,
        prefix: Option<Ipv6Prefix>,
    ) -> Result<Option<Ipv6Addr>, Self> {
        let (Some(client_id), Some(router_ip)) = (client_id, router_ip) else {
            return Ok(router_ip);
        };

        let Some(prefix) = prefix else {
            return Err(Self::NoIpv6Prefix);
        };

        let ip = prefix.with_client_id(client_id);
        if ip == router_ip {
            return Err(Self::ClientIpSameAsUpdateIP {
                router_ip,
                client_id,
                prefix,
            });
        }

        Ok(Some(ip))
    }
}

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
    fn from(
        SavedIps {
            ipv4,
            ipv6,
            ipv6prefix: _,
        }: SavedIps,
    ) -> Self {
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
                let ips = saved.get(domain).cloned()?;
                RecordUpdate {
                    domain,
                    record,
                    prefix: ips.ipv6prefix,
                    ips: ips.into(),
                } // ignore saved data, we are restoring it
                .into_actions(None)
                .inspect_err(|err| {
                    tracing::warn!("couldn't restore saved data for {domain}: {err}");
                })
                .ok()
            })
            .flatten()
    }

    /// Create a set of [`Action`]s reassigning the domains in `records` to the
    /// specified [`IpAddr`]
    #[cfg(test)]
    fn from_record(domain: &'a str, record: &'a Record, ips: IpPair) -> impl Iterator<Item = Self> {
        ips.ips()
            .filter(|&ip| record.ip_type.valid_for_type(ip))
            .map(move |to| Self::Reassign {
                domain,
                to,
                ttl: *record.ttl,
            })
            .chain({
                match (record.router_domain.as_deref(), ips.ipv6) {
                    (Some(domain), Some(ip)) if record.ip_type.accepts_ipv6() => {
                        Some(Self::Reassign {
                            domain,
                            to: ip.into(),
                            ttl: *record.ttl,
                        })
                    }
                    (Some(_) | None, Some(_) | None) => None,
                }
            })
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

        assert_snapshot!(String::from_utf8(buf).unwrap(), @r"
        server 127.0.0.1
        update delete example.com. 600 IN A
        update add    example.com. 600 IN A 127.0.0.1
        send
        quit
        ");
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

        assert_snapshot!(String::from_utf8(buf).unwrap(), @r"
        server 127.0.0.1
        update delete example.com. 600 IN AAAA
        update add    example.com. 600 IN AAAA ::1
        send
        quit
        ");
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

        assert_snapshot!(String::from_utf8(buf).unwrap(), @r"
        server 127.0.0.1
        update delete example.com. 600 IN A
        update add    example.com. 600 IN A 127.0.0.1
        update delete example.com. 600 IN AAAA
        update add    example.com. 600 IN AAAA ::1
        send
        quit
        ");
    }
}
