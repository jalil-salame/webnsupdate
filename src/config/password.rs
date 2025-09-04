use std::path::Path;

use super::default;

/// Password settings
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct Password {
    /// File containing password to match against
    ///
    /// Should be of the format `username:password` and contain a single
    /// password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<Box<Path>>,

    /// Salt to get more unique hashed passwords and prevent table based attacks
    #[serde(default = "default::salt")]
    pub salt: Box<str>,

    /// Unknown fields that will be ignored
    #[serde(default, flatten, skip_serializing)]
    #[expect(clippy::zero_sized_map_values, reason = "needed for serde")]
    ignored_fields: super::error::IgnoredFields,
}

impl Default for Password {
    fn default() -> Self {
        Self {
            file: None,
            salt: default::salt(),
            ignored_fields: super::error::IgnoredFields::new(),
        }
    }
}

impl Password {
    /// Check for ignored fields and drop them from the struct
    pub fn drop_ignored_fields(&mut self) -> Result<(), super::error::IgnoredFieldsError> {
        super::error::IgnoredFieldsError::consume(&mut self.ignored_fields)
    }

    /// Verify the configuration
    pub fn verify(&mut self) -> Result<(), super::error::ConfigIssues> {
        super::error::ConfigIssues::new(Box::from("password"))
            // check for any ignored fields
            .add_issue(self.drop_ignored_fields())
            // Turn into a hard error
            .into_err()
    }
}
