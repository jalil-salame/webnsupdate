use std::net::SocketAddr;
use std::path::Path;

use super::default;

/// Webserver settings
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct Server {
    /// Ip address and port of the server
    #[serde(default = "default::address")]
    pub address: SocketAddr,

    /// Set client IP source
    ///
    /// see: <https://docs.rs/axum-client-ip/latest/axum_client_ip/enum.ClientIpSource.html>
    #[serde(default = "default::ip_source")]
    pub ip_source: super::ClientIpSource,

    /// Keyfile `nsupdate` should use
    ///
    /// If specified, then `webnsupdate` must have read access to the file
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_file: Option<Box<Path>>,

    /// Unknown fields that will be ignored
    #[serde(default, flatten, skip_serializing)]
    #[expect(clippy::zero_sized_map_values, reason = "needed for serde")]
    ignored_fields: super::error::IgnoredFields,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            address: default::address(),
            ip_source: default::ip_source(),
            key_file: None,
            ignored_fields: super::error::IgnoredFields::new(),
        }
    }
}

impl Server {
    /// Check for ignored fields and drop them from the struct
    pub fn drop_ignored_fields(&mut self) -> Result<(), super::error::IgnoredFieldsError> {
        super::error::IgnoredFieldsError::consume(&mut self.ignored_fields)
    }

    /// Verify the configuration
    pub fn verify(&mut self) -> Result<(), super::error::ConfigIssues> {
        super::error::ConfigIssues::new(Box::from("server"))
            // check for any ignored fields
            .add_issue(self.drop_ignored_fields())
            // Turn into a hard error
            .into_err()
    }
}
