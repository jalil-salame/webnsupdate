use std::{net::SocketAddr, path::Path};

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
}
