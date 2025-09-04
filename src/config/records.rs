use std::net::{IpAddr, Ipv6Addr};

use super::default;

/// Records settings
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct Records {
    /// Time To Live (in seconds) to set on the DNS records
    #[serde(default = "default::ttl", with = "serde_humantime")]
    pub ttl: humantime::Duration,

    /// List of domain names for which to update the IP when an update is requested
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[allow(clippy::struct_field_names)]
    pub records: Vec<Box<str>>,

    /// If provided, when an IPv6 prefix is provided with an update, this will be used to derive
    /// the full IPv6 address of the client
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "unused outside of tests, for now")
    )]
    pub client_id: Option<Ipv6Addr>,

    /// If a client id is provided the ipv6 update will be ignored (only the prefix will be used).
    /// This domain will point to the ipv6 address instead of the address derived from the client
    /// id (usually this is the router).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_domain: Option<Box<str>>,

    /// Set which IPs to allow updating (ipv4, ipv6 or both)
    #[serde(default = "default::ip_type")]
    pub ip_type: super::IpType,
}

#[derive(Debug, miette::Diagnostic, thiserror::Error)]
#[error("the configuration was invalid")]
pub struct Invalid {
    #[related]
    pub invalid_records: Vec<miette::Error>,
}

impl Records {
    pub fn verify(&self) -> Result<(), Invalid> {
        let mut invalid_records: Vec<miette::Error> = self
            .records
            .iter()
            .filter_map(|record| crate::records::validate_record_str(record).err())
            .collect();

        invalid_records.extend(
            self.router_domain
                .as_ref()
                .and_then(|domain| crate::records::validate_record_str(domain).err()),
        );

        let err = Invalid { invalid_records };

        if err.invalid_records.is_empty() {
            Ok(())
        } else {
            Err(err)
        }
    }
}

#[derive(Debug, Default, Clone, Copy, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub enum IpType {
    #[default]
    Both,
    Ipv4Only,
    Ipv6Only,
}

impl IpType {
    pub fn valid_for_type(self, ip: IpAddr) -> bool {
        match self {
            IpType::Both => true,
            IpType::Ipv4Only => ip.is_ipv4(),
            IpType::Ipv6Only => ip.is_ipv6(),
        }
    }
}

impl std::fmt::Display for IpType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpType::Both => f.write_str("both"),
            IpType::Ipv4Only => f.write_str("ipv4-only"),
            IpType::Ipv6Only => f.write_str("ipv6-only"),
        }
    }
}

impl std::str::FromStr for IpType {
    type Err = miette::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "both" => Ok(Self::Both),
            "ipv4-only" => Ok(Self::Ipv4Only),
            "ipv6-only" => Ok(Self::Ipv6Only),
            _ => miette::bail!("expected one of 'ipv4-only', 'ipv6-only' or 'both', got '{s}'"),
        }
    }
}

/// Implementations of serialize and deserialize for [`humantime::Duration`]
mod serde_humantime {
    pub fn deserialize<'de, D>(de: D) -> Result<humantime::Duration, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = humantime::Duration;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a duration (e.g. 5s)")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.parse().map_err(E::custom)
            }
        }
        de.deserialize_str(Visitor)
    }

    #[cfg(test)]
    pub fn serialize<S>(duration: &humantime::Duration, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ser.serialize_str(&duration.to_string())
    }
}
