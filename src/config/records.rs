use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv6Addr;

use super::default;

/// A mapping from a domain to a record
#[derive(Default, Clone, Debug, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct Records(HashMap<Box<str>, Record>);

impl Records {
    /// Number of configured [`Record`]s
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn get(&self, domain: &str) -> Option<&Record> {
        self.0.get(domain)
    }

    /// Get all the (domain, [`Record`]) pairs
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Record)> {
        self.0
            .iter()
            .map(|(domain, record)| (domain.as_ref(), record))
    }

    /// Get all the configured domains
    pub fn domains(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(Box::as_ref)
    }

    /// Get all the [`Record`]s
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.0.values()
    }

    /// Get all the configured [`Record::router_domain`]
    pub fn router_domains(&self) -> impl Iterator<Item = &'_ str> {
        self.records()
            .filter_map(|record| record.router_domain.as_deref())
    }

    /// Ensure the domains are valid record strings
    fn valid_record_domains(&self) -> impl Iterator<Item = miette::Error> {
        fn validate_err(record: &str) -> Option<miette::Error> {
            crate::records::validate_record_str(record).err()
        }

        self.domains()
            .chain(self.router_domains())
            .filter_map(validate_err)
    }

    /// Check that there are no duplicated domains
    fn duplicate_domains(&self) -> impl Iterator<Item = miette::Error> {
        // router_domain is optional so it will have at most the same elements as
        // domains
        let router_domains: std::collections::HashSet<_> = self.router_domains().collect();

        self.domains()
            .filter(move |&domain| router_domains.contains(domain))
            .map(|domain| {
                miette::miette!(
                    "domain {domain:?} is present both as the `domain` of a record and as the \
                     `router_domain`, this is not supported."
                )
            })
    }

    /// Check that the domains are valid
    fn invalid_records(&self) -> Result<(), Invalid> {
        let invalid_records: Vec<_> = self
            .valid_record_domains()
            .chain(self.duplicate_domains())
            .collect();

        if invalid_records.is_empty() {
            return Ok(());
        }

        Err(Invalid { invalid_records })
    }

    /// Ensure at least one domain is configured
    fn at_least_one_domain(&self) -> miette::Result<()> {
        if self.len() == 0 {
            Err(miette::miette!("no domain is configured for updates"))
        } else {
            Ok(())
        }
    }

    pub fn verify(&mut self) -> Result<(), super::error::ConfigIssues> {
        self.0
            .iter_mut()
            .fold(
                super::error::ConfigIssues::new(Box::from("records")),
                |issues, (domain, records)| {
                    issues.add_issue(
                        records
                            .verify()
                            .map_err(|issues| issues.set_path(format!("records.{domain:?}"))),
                    )
                },
            )
            .add_issue(self.invalid_records())
            .add_issue(self.at_least_one_domain())
            .into_err()
    }
}

/// Records settings
#[derive(Clone, Debug, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct Record {
    /// Time To Live (in seconds) to set on the DNS records
    #[serde(default = "default::ttl", with = "serde_humantime")]
    pub ttl: humantime::Duration,

    /// If provided, when an IPv6 prefix is provided with an update, this will
    /// be used to derive the full IPv6 address of the client
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<Ipv6Addr>,

    /// If a client id is provided the ipv6 update will be ignored (only the
    /// prefix will be used). This domain will point to the ipv6 address
    /// instead of the address derived from the client id (usually this is
    /// the router).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_domain: Option<Box<str>>,

    /// Set which IPs to allow updating (ipv4, ipv6 or both)
    #[serde(default = "default::ip_type")]
    pub ip_type: IpType,

    /// Unknown fields that will be ignored
    #[serde(default, flatten, skip_serializing)]
    #[expect(clippy::zero_sized_map_values, reason = "needed for serde")]
    ignored_fields: super::error::IgnoredFields,
}

impl Record {
    #[cfg(test)]
    pub fn new() -> Self {
        Self {
            ttl: crate::DEFAULT_TTL.into(),
            client_id: None,
            router_domain: None,
            ip_type: IpType::Both,
            #[expect(clippy::zero_sized_map_values, reason = "needed for serde")]
            ignored_fields: super::error::IgnoredFields::new(),
        }
    }

    /// Check for ignored fields and drop them from the struct
    pub fn drop_ignored_fields(&mut self) -> Result<(), super::error::IgnoredFieldsError> {
        super::error::IgnoredFieldsError::consume(&mut self.ignored_fields)
    }

    /// Verify the configuration
    pub fn verify(&mut self) -> Result<(), super::error::ConfigIssues> {
        super::error::ConfigIssues::new(None)
            // check for any ignored fields
            .add_issue(self.drop_ignored_fields())
            // Turn into a hard error
            .into_err()
    }
}

#[derive(Debug, miette::Diagnostic, thiserror::Error)]
#[error("the configuration was invalid")]
pub struct Invalid {
    #[related]
    pub invalid_records: Vec<miette::Error>,
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

    pub fn accepts_ipv4(self) -> bool {
        match self {
            IpType::Both | IpType::Ipv4Only => true,
            IpType::Ipv6Only => false,
        }
    }

    pub fn accepts_ipv6(self) -> bool {
        match self {
            IpType::Both | IpType::Ipv6Only => true,
            IpType::Ipv4Only => false,
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
