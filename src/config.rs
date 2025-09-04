use std::fs::File;

use axum_client_ip::ClientIpSource;
use miette::Context;
use miette::IntoDiagnostic;

mod default;
mod error;
mod password;
mod records;
mod server;

pub use password::Password;
pub use records::IpType;
pub use records::Record;
pub use records::Records;
pub use server::Server;

#[derive(Debug, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct Config {
    /// Server Configuration
    #[serde(default)]
    pub server: Server,

    /// Password Configuration
    #[serde(default)]
    pub password: Password,

    /// Records Configuration
    #[serde(default)]
    pub records: Records,

    /// The config schema (used for lsp completions)
    #[serde(default, rename = "$schema", skip_serializing)]
    pub _schema: serde::de::IgnoredAny,

    /// Unknown fields that will be ignored
    #[serde(default, flatten, skip_serializing)]
    #[expect(clippy::zero_sized_map_values, reason = "needed for serde")]
    ignored_fields: error::IgnoredFields,
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
    pub fn verified(mut self) -> miette::Result<Self> {
        self.verify()?;
        Ok(self)
    }

    /// Check for ignored fields and drop them from the struct
    pub fn drop_ignored_fields(&mut self) -> Result<(), error::IgnoredFieldsError> {
        error::IgnoredFieldsError::consume(&mut self.ignored_fields)
    }

    /// Verify the configuration
    pub fn verify(&mut self) -> Result<(), error::ConfigIssues> {
        error::ConfigIssues::new(None)
            // check for any ignored fields
            .add_issue(self.drop_ignored_fields())
            // check for any issues with the server config
            .add_issue(self.server.verify())
            // check for any issues with the password config
            .add_issue(self.password.verify())
            // check for any issues with the records config
            .add_issue(self.records.verify())
            // Turn into a hard error
            .into_err()
    }
}

#[test]
fn default_values_config_snapshot() {
    let config: Config = serde_json::from_str("{}").unwrap();
    insta::assert_json_snapshot!(config, @r#"
    {
      "server": {
        "address": "127.0.0.1:5353",
        "ip_source": "RightmostXForwardedFor"
      },
      "password": {
        "salt": "UpdateMyDNS"
      },
      "records": {}
    }
    "#);
}
