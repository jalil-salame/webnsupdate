use std::borrow::Cow;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use axum::extract::Query;
use axum::extract::State;
use axum::http::StatusCode;
use axum_client_ip::ClientIp;
use miette::Context as _;
use miette::IntoDiagnostic as _;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::AppState;
use crate::config::IpType;
use crate::config::Record;
use crate::config::Records;
use crate::nsupdate::IpPair;

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FritzBoxUpdateParams {
    /// The domain that should be updated
    #[serde(default, deserialize_with = "empty_string_as_none")]
    domain: Option<String>,
    /// IPv4 address for the domain
    #[serde(default, deserialize_with = "empty_string_as_none")]
    ipv4: Option<Ipv4Addr>,
    /// IPv6 address for the domain
    #[serde(default, deserialize_with = "empty_string_as_none")]
    ipv6: Option<Ipv6Addr>,
    /// IPv6 prefix for the home network
    #[serde(default, deserialize_with = "empty_string_as_none")]
    ipv6prefix: Option<Ipv6Prefix>,
    /// Whether the networks uses both IPv4 and IPv6
    #[serde(default, deserialize_with = "empty_string_as_none")]
    dualstack: Option<String>,
}

impl FritzBoxUpdateParams {
    fn is_empty(&self) -> bool {
        let Self {
            domain,
            ipv4,
            ipv6,
            ipv6prefix,
            dualstack,
        } = self;
        domain.is_none()
            & ipv4.is_none()
            & ipv6.is_none()
            & ipv6prefix.is_none()
            & dualstack.is_none()
    }
}

#[derive(Clone, Copy, Debug)]
struct Ipv6Prefix {
    prefix: Ipv6Addr,
    length: u32,
}

impl std::fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { prefix, length } = self;
        write!(f, "{prefix}/{length}")
    }
}

impl std::str::FromStr for Ipv6Prefix {
    type Err = miette::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (addr, len) = s.split_once('/').wrap_err("missing `/` in ipv6 prefix")?;
        Ok(Self {
            prefix: addr
                .parse()
                .into_diagnostic()
                .wrap_err("invalid ipv6 address for ipv6 prefix")?,
            length: len
                .parse()
                .into_diagnostic()
                .wrap_err("invalid length for ipv6 prefix")?,
        })
    }
}

/// Serde deserialization decorator to map empty Strings to None,
///
/// Adapted from: <https://github.com/tokio-rs/axum/blob/main/examples/query-params-with-empty-strings/src/main.rs>
fn empty_string_as_none<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    use serde::Deserialize;

    let opt = Option::<std::borrow::Cow<'de, str>>::deserialize(de)?;
    match opt.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => s.parse::<T>().map_err(serde::de::Error::custom).map(Some),
    }
}

#[derive(Debug, miette::Diagnostic, thiserror::Error)]
pub enum UpdateError {
    #[error("no configured domains to update")]
    NoConfiguredDomains,

    #[error(
        "cannot determine which domain to update since the request didn't specify it and we have \
         {records} domains configured"
    )]
    AmbiguousDomain { records: usize },

    #[error("running in {ip_type} mode")]
    WrongIpType { ip_type: IpType },

    #[error("Nothing to do (e.g. we are ipv4-only but an ipv6 update was requested)")]
    NoActions,

    #[error("nsupdate failed, check server logs")]
    NsupdateError,

    #[error("failed to update records")]
    FailedToUpdateRecords(#[from] std::io::Error),

    #[error("failed to provide an IP for the update")]
    NoIpForUpdate,

    #[error("couldn't find a record for '{domain}'")]
    NoRecordForDomain { domain: Box<str> },
}

impl UpdateError {
    fn status(&self) -> StatusCode {
        match self {
            UpdateError::FailedToUpdateRecords(_)
            | UpdateError::NsupdateError
            | UpdateError::NoActions
            | UpdateError::NoConfiguredDomains => StatusCode::INTERNAL_SERVER_ERROR,
            UpdateError::NoRecordForDomain { .. }
            | UpdateError::NoIpForUpdate
            | UpdateError::AmbiguousDomain { .. } => StatusCode::BAD_REQUEST,
            UpdateError::WrongIpType { .. } => StatusCode::CONFLICT,
        }
    }
}

impl axum::response::IntoResponse for UpdateError {
    fn into_response(self) -> axum::response::Response {
        let mut response = axum::response::Response::new(self.to_string().into());
        *response.status_mut() = self.status();
        response
    }
}

fn single_record(ip: IpAddr, records: &Records) -> Result<(&str, &Record), UpdateError> {
    let mut iter = records.iter();

    let Some((domain, record)) = iter.next() else {
        tracing::error!("state says no records are configured, this shouldn't happen");

        return Err(UpdateError::NoConfiguredDomains);
    };

    let None = iter.next() else {
        warn!(
            "rejecting update from {ip} since no domain was provided and we have {} configured \
             domains",
            records.len()
        );
        return Err(UpdateError::AmbiguousDomain {
            records: records.len(),
        });
    };

    Ok((domain, record))
}

#[tracing::instrument(skip(state), level = "trace", ret(level = "info"))]
pub async fn update_records(
    State(state): State<crate::AppState<'static>>,
    ClientIp(ip): ClientIp,
    Query(update_params): Query<FritzBoxUpdateParams>,
) -> Result<&'static str, UpdateError> {
    info!("accepted update from {ip}");

    if update_params.is_empty() {
        let (domain, record) = single_record(ip, &state.records)?;

        if !record.ip_type.valid_for_type(ip) {
            warn!(
                "rejecting update from {ip} as we are running a {} filter",
                record.ip_type
            );
            return Err(UpdateError::WrongIpType {
                ip_type: record.ip_type,
            });
        }

        return trigger_update(domain, record, IpPair::from(ip), &state).await;
    }

    // FIXME: mark suspicious updates (where IP doesn't match the update_ip) and
    // reject them based on policy

    let FritzBoxUpdateParams {
        domain,
        ipv4,
        ipv6,
        ipv6prefix: _,
        dualstack: _,
    } = update_params;

    let ips = IpPair::new(ipv4, ipv6).add_if_missing(ip);
    tracing::debug!("requested update for {ips:?}");

    if ips.is_empty() {
        return Err(UpdateError::NoIpForUpdate);
    }

    let Some(domain) = domain.as_deref() else {
        let (domain, record) = single_record(ip, &state.records)?;

        return trigger_update(domain, record, ips, &state).await;
    };

    // add trailing comma to domain if missing
    let domain = if domain.ends_with('.') {
        Cow::Borrowed(domain)
    } else {
        Cow::Owned(format!("{domain}."))
    };

    let Some(record) = state.records.get(&domain) else {
        warn!("requested update for {domain} but had no matching record");

        return Err(UpdateError::NoRecordForDomain {
            domain: domain.into(),
        });
    };

    return trigger_update(&domain, record, ips, &state).await;
}

#[tracing::instrument(skip(record, state, ips), level = "trace", ret(level = "info"))]
async fn trigger_update(
    domain: &str,
    record: &Record,
    ips: IpPair,
    state: &AppState<'static>,
) -> Result<&'static str, UpdateError> {
    let mut actions = crate::nsupdate::Action::from_record(domain, record, ips).peekable();

    if actions.peek().is_none() {
        return Err(UpdateError::NoActions);
    }

    match crate::nsupdate::nsupdate(state.key_file, actions).await {
        Ok(status) if status.success() => {
            // Update saved data
            state.saved_data.write().await.update(domain, ips);

            // trigger a save to disk of the state
            state.trigger_save();

            Ok("Successfully updated IP of records!\n")
        }
        Ok(status) => {
            error!("nsupdate failed with code {status}");
            Err(UpdateError::NsupdateError)
        }
        Err(error) => Err(UpdateError::FailedToUpdateRecords(error)),
    }
}

#[cfg(test)]
mod parse_query_params {
    use axum::extract::Query;
    use axum::http::Uri;

    use super::FritzBoxUpdateParams;

    #[test]
    fn no_params() {
        let uri = Uri::builder().path_and_query("/update").build().unwrap();
        let query: Query<FritzBoxUpdateParams> = Query::try_from_uri(&uri).unwrap();
        insta::assert_debug_snapshot!(query, @r#"
    Query(
        FritzBoxUpdateParams {
            domain: None,
            ipv4: None,
            ipv6: None,
            ipv6prefix: None,
            dualstack: None,
        },
    )
    "#);
    }

    #[test]
    fn ipv4() {
        let uri = Uri::builder()
            .path_and_query("/update?ipv4=1.2.3.4")
            .build()
            .unwrap();
        let query: Query<FritzBoxUpdateParams> = Query::try_from_uri(&uri).unwrap();
        insta::assert_debug_snapshot!(query, @r#"
    Query(
        FritzBoxUpdateParams {
            domain: None,
            ipv4: Some(
                1.2.3.4,
            ),
            ipv6: None,
            ipv6prefix: None,
            dualstack: None,
        },
    )
    "#);
    }

    #[test]
    fn ipv6() {
        let uri = Uri::builder()
            .path_and_query("/update?ipv6=%3A%3A1234")
            .build()
            .unwrap();
        let query: Query<FritzBoxUpdateParams> = Query::try_from_uri(&uri).unwrap();
        insta::assert_debug_snapshot!(query, @r#"
    Query(
        FritzBoxUpdateParams {
            domain: None,
            ipv4: None,
            ipv6: Some(
                ::1234,
            ),
            ipv6prefix: None,
            dualstack: None,
        },
    )
    "#);
    }

    #[test]
    fn ipv4_and_ipv6() {
        let uri = Uri::builder()
            .path_and_query("/update?ipv4=1.2.3.4&ipv6=%3A%3A1234")
            .build()
            .unwrap();
        let query: Query<FritzBoxUpdateParams> = Query::try_from_uri(&uri).unwrap();
        insta::assert_debug_snapshot!(query, @r#"
    Query(
        FritzBoxUpdateParams {
            domain: None,
            ipv4: Some(
                1.2.3.4,
            ),
            ipv6: Some(
                ::1234,
            ),
            ipv6prefix: None,
            dualstack: None,
        },
    )
    "#);
    }

    #[test]
    fn ipv4_and_empty_ipv6() {
        let uri = Uri::builder()
            .path_and_query("/update?ipv4=1.2.3.4&ipv6=")
            .build()
            .unwrap();
        let query: Query<FritzBoxUpdateParams> = Query::try_from_uri(&uri).unwrap();
        insta::assert_debug_snapshot!(query, @r#"
    Query(
        FritzBoxUpdateParams {
            domain: None,
            ipv4: Some(
                1.2.3.4,
            ),
            ipv6: None,
            ipv6prefix: None,
            dualstack: None,
        },
    )
    "#);
    }

    #[test]
    fn empty_ipv4_and_ipv6() {
        let uri = Uri::builder()
            .path_and_query("/update?ipv4=&ipv6=%3A%3A1234")
            .build()
            .unwrap();
        let query: Query<FritzBoxUpdateParams> = Query::try_from_uri(&uri).unwrap();
        insta::assert_debug_snapshot!(query, @r#"
    Query(
        FritzBoxUpdateParams {
            domain: None,
            ipv4: None,
            ipv6: Some(
                ::1234,
            ),
            ipv6prefix: None,
            dualstack: None,
        },
    )
    "#);
    }
}
