use std::path::Path;

use super::default;

/// Password settings
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct Password {
    /// File containing password to match against
    ///
    /// Should be of the format `username:password` and contain a single password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<Box<Path>>,

    /// Salt to get more unique hashed passwords and prevent table based attacks
    #[serde(default = "default::salt")]
    pub salt: Box<str>,
}
