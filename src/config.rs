use std::fs::File;

use axum_client_ip::ClientIpSource;
use miette::{Context, IntoDiagnostic};

mod default;
mod password;
mod records;
mod server;

pub use password::Password;
pub use records::{IpType, Records};
pub use server::Server;

#[derive(Debug, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct Config {
    /// Server Configuration
    pub server: Server,

    /// Password Configuration
    pub password: Password,

    /// Records Configuration
    pub records: Records,

    /// The config schema (used for lsp completions)
    #[serde(default, rename = "$schema", skip_serializing)]
    pub _schema: serde::de::IgnoredAny,
}

impl Config {
    /// Load the configuration without verifying it
    pub fn load(path: &std::path::Path) -> miette::Result<Self> {
        serde_json::from_reader::<File, Self>(
            File::open(path)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed open {}", path.display()))?,
        )
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to load configuration from {}", path.display()))
    }

    /// Ensure only a verified configuration is returned
    pub fn verified(self) -> miette::Result<Self> {
        self.verify()?;
        Ok(self)
    }

    /// Verify the configuration
    pub fn verify(&self) -> Result<(), records::Invalid> {
        self.records.verify()
    }
}

#[test]
fn default_values_config_snapshot() {
    let config: Config = serde_json::from_str("{}").unwrap();
    insta::assert_json_snapshot!(config, @r#"
    {
      "address": "127.0.0.1:5353",
      "salt": "UpdateMyDNS",
      "ttl": "1m",
      "ip_source": "RightmostXForwardedFor",
      "ip_type": "Both"
    }
    "#);
}
