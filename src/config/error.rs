use std::collections::BTreeMap;

use miette::Diagnostic;

/// Extra fields that are present in a JSON blob, but we ignore
#[expect(clippy::zero_sized_map_values, reason = "needed for serde")]
pub type IgnoredFields = BTreeMap<Box<str>, serde::de::IgnoredAny>;

#[derive(Debug, Diagnostic, thiserror::Error)]
#[error("the following unknown fields are ignored: {0:?}")]
#[diagnostic(
    severity = "warn",
    help = "you might have made a typo, or are using the wrong version of webnsupdate"
)]
/// Error for when a field is ignored
pub struct IgnoredFieldsError(Box<[Box<str>]>);

impl IgnoredFieldsError {
    #[expect(clippy::zero_sized_map_values, reason = "needed for serde")]
    pub fn consume(fields: &mut IgnoredFields) -> Result<(), Self> {
        let mut ignored = BTreeMap::new();
        std::mem::swap(fields, &mut ignored);

        if ignored.is_empty() {
            return Ok(());
        }

        Err(Self::from(ignored))
    }
}

#[expect(clippy::zero_sized_map_values, reason = "needed for serde")]
impl From<IgnoredFields> for IgnoredFieldsError {
    fn from(value: IgnoredFields) -> Self {
        Self(value.into_keys().collect())
    }
}

#[derive(Debug, Diagnostic, thiserror::Error)]
pub struct ConfigIssues {
    path: Option<Box<str>>,

    #[related]
    issues: Vec<Box<dyn Diagnostic + Send + Sync + 'static>>,
}

impl ConfigIssues {
    pub fn new(path: impl Into<Option<Box<str>>>) -> Self {
        let path: Option<Box<str>> = path.into();

        Self {
            path,
            issues: Vec::new(),
        }
    }

    pub fn add_issue<E>(mut self, issue: Result<(), E>) -> Self
    where
        E: Into<Box<dyn Diagnostic + Send + Sync + 'static>>,
    {
        if let Err(err) = issue {
            self.issues.push(err.into());
        }

        self
    }

    pub fn into_err(self) -> Result<(), Self> {
        if self.issues.is_empty() {
            Ok(())
        } else {
            Err(self)
        }
    }

    pub fn set_path(mut self, path: impl Into<Box<str>>) -> Self {
        self.path = Some(path.into());
        self
    }
}

impl std::fmt::Display for ConfigIssues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("configuration")?;
        if let Some(path) = self.path.as_deref() {
            write!(f, " of `{path}`")?;
        }
        f.write_str(" had issues")
    }
}
