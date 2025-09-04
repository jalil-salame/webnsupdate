//! State saved on disk

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::path::Path;
use std::sync::Arc;

use miette::Context as _;
use miette::IntoDiagnostic as _;
use tokio::sync::Notify;
use tokio::sync::RwLock;
use tracing::error;

use crate::nsupdate::IpPair;
use crate::update_handler::Ipv6Prefix;

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
/// Data that will be persisted to disk
pub struct SavedData {
    /// Per Domain data
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    per_domain: HashMap<Box<str>, SavedIps>,
}

impl SavedData {
    pub fn update(&mut self, domain: impl Into<Box<str>>, ips: IpPair, prefix: Option<Ipv6Prefix>) {
        let entry = self.per_domain.entry(domain.into()).or_default();

        if let Some(prefix) = prefix {
            entry.update_prefix(prefix);
        }

        for ip in ips.ips() {
            entry.update(ip);
        }
    }

    pub fn get(&self, domain: &str) -> Option<&SavedIps> {
        self.per_domain.get(domain)
    }

    pub fn load(path: &Path) -> Result<Option<Self>, LoadSavedIpsError> {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,

            // File not found
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),

            // Failed to open file
            Err(err) => return Err(LoadSavedIpsErrorKind::IO(err).with_path(path)),
        };

        serde_json::from_reader(std::io::BufReader::new(file))
            .map(Some)
            .map_err(|err| LoadSavedIpsErrorKind::Parse(err).with_path(path))
    }
}

pub struct SaveDataTask<'p> {
    trigger: Arc<Notify>,
    state: Arc<RwLock<SavedData>>,
    path: &'p Path,
}

impl<'p> SaveDataTask<'p> {
    pub fn from_app_state(state: &crate::AppState<'p>) -> Self {
        Self {
            trigger: state.trigger.clone(),
            state: state.saved_data.clone(),
            path: state.ip_file,
        }
    }

    pub async fn save_state_task(&self) -> ! {
        let mut buf = Vec::new();
        loop {
            // wait for a notification
            let () = self.trigger.notified().await;

            // trigger save to disk
            if let Err(err) = self.trigger_save_impl(&mut buf).await {
                error!("failed to save state: {err}");
            }
        }
    }

    pub async fn trigger_save(&self) -> miette::Result<()> {
        let mut buf = Vec::new();
        self.trigger_save_impl(&mut buf).await
    }

    #[tracing::instrument(name = "trigger_save", fields(path = %self.path.display()), skip(buf, self), err)]
    async fn trigger_save_impl(&self, mut buf: &mut Vec<u8>) -> miette::Result<()> {
        buf.clear();

        // Serialize data to buffer
        tracing::debug!("serializing state to buffer");
        serde_json::to_writer(&mut buf, &*self.state.read().await)
            .into_diagnostic()
            .wrap_err("failed to serialize state")?;

        // Write data to file
        //
        // This is synchronous to ensure it is not cancelled in the middle of the
        // operation.
        tracing::debug!("writing state to disk");
        std::fs::write(self.path, buf.as_slice())
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to save state to {}", self.path.display()))
    }
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
/// The saved IPs for a domain
pub struct SavedIps {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<Ipv4Addr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<Ipv6Addr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6prefix: Option<Ipv6Prefix>,
}

#[derive(Debug, miette::Diagnostic, thiserror::Error)]
#[error("failed to load saved IPs from {}", path.display())]
pub struct LoadSavedIpsError {
    path: Box<Path>,

    #[source]
    kind: LoadSavedIpsErrorKind,
}

impl SavedIps {
    pub fn update(&mut self, ip: IpAddr) {
        match ip {
            IpAddr::V4(ipv4_addr) => self.ipv4 = Some(ipv4_addr),
            IpAddr::V6(ipv6_addr) => self.ipv6 = Some(ipv6_addr),
        }
    }

    pub fn update_prefix(&mut self, prefix: Ipv6Prefix) {
        self.ipv6prefix = Some(prefix);
    }
}

#[derive(Debug, miette::Diagnostic, thiserror::Error)]
enum LoadSavedIpsErrorKind {
    #[error("failed to read saved data")]
    IO(#[from] std::io::Error),

    #[error("failed to parse saved data")]
    Parse(#[from] serde_json::Error),
}

impl LoadSavedIpsErrorKind {
    fn with_path(self, path: impl Into<Box<Path>>) -> LoadSavedIpsError {
        LoadSavedIpsError {
            path: path.into(),
            kind: self,
        }
    }
}
