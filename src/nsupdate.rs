use std::{
    ffi::OsStr,
    net::IpAddr,
    path::Path,
    process::{ExitStatus, Stdio},
    time::Duration,
};

use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

#[tracing::instrument(level = "trace", ret(level = "warn"))]
pub async fn nsupdate(
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use insta::assert_snapshot;

    use super::update_ns_records;
    use crate::DEFAULT_TTL;

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
