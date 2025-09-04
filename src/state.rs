//! State saved on disk

use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    str::FromStr,
};

use miette::{Context, IntoDiagnostic as _};

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct SavedIPs {
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv4: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv6: Option<Ipv6Addr>,
}

impl FromStr for SavedIPs {
    type Err = miette::Error;

    fn from_str(data: &str) -> Result<Self, Self::Err> {
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

impl SavedIPs {
    pub fn update(&mut self, ip: IpAddr) {
        match ip {
            IpAddr::V4(ipv4_addr) => self.ipv4 = Some(ipv4_addr),
            IpAddr::V6(ipv6_addr) => self.ipv6 = Some(ipv6_addr),
        }
    }

    pub fn ips(&self) -> impl Iterator<Item = IpAddr> + use<> {
        self.ipv4
            .map(IpAddr::V4)
            .into_iter()
            .chain(self.ipv6.map(IpAddr::V6))
    }

    pub fn load(path: &Path) -> miette::Result<Option<Self>> {
        let data = match std::fs::read_to_string(path) {
            // Read file
            Ok(data) => data,

            // File not found
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),

            // Failed to read file
            Err(err) => {
                return Err(err)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to open file at {}", path.display()));
            }
        };

        data.parse().map(Some)
    }
}
