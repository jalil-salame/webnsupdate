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
use crate::nsupdate::RecordUpdate;

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

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Ipv6Prefix {
    prefix: Ipv6Addr,
    length: u32,
}

impl Ipv6Prefix {
    /// Create an [`Ipv6Addr`] from a prefix and a client id
    pub fn with_client_id(self, client_id: Ipv6Addr) -> Ipv6Addr {
        let Self { prefix, length } = self;
        // Clear the last `length` bits
        let prefix_mask = u128::MAX << length;
        let client_mask = !prefix_mask;
        let prefix = prefix.to_bits();
        let client = client_id.to_bits();
        debug_assert_eq!(
            prefix & client_mask,
            0,
            "prefix contains bits in client id part"
        );
        debug_assert_eq!(
            client & prefix_mask,
            0,
            "client id contains bits in prefix part"
        );
        Ipv6Addr::from_bits((prefix & prefix_mask) | (client & client_mask))
    }
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

impl From<Ipv6Prefix> for String {
    fn from(value: Ipv6Prefix) -> Self {
        value.to_string()
    }
}

impl TryFrom<String> for Ipv6Prefix {
    type Error = <Self as std::str::FromStr>::Err;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
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

    #[error("nothing to do (e.g. we are ipv4-only but an ipv6 update was requested)")]
    NoActions,

    #[error(transparent)]
    BadUpdate(
        #[from]
        #[diagnostic_source]
        crate::nsupdate::RecordUpdateError,
    ),

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
            UpdateError::BadUpdate(_)
            | UpdateError::NoRecordForDomain { .. }
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

#[tracing::instrument(skip_all, level = "trace", ret(level = "info"))]
async fn update_from_ip(
    state: crate::AppState<'static>,
    ip: IpAddr,
) -> Result<&'static str, UpdateError> {
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

    trigger_update(
        RecordUpdate {
            domain,
            record,
            ips: IpPair::from(ip),
            prefix: None,
        },
        &state,
    )
    .await
}

#[tracing::instrument(skip(state, ip), level = "trace", ret(level = "info"))]
async fn update_from_query(
    state: crate::AppState<'static>,
    ip: IpAddr,
    update_params: FritzBoxUpdateParams,
) -> Result<&'static str, UpdateError> {
    // FIXME: mark suspicious updates (where IP doesn't match the update_ip) and
    // reject them based on policy
    let FritzBoxUpdateParams {
        domain,
        ipv4,
        ipv6,
        ipv6prefix: prefix,
        dualstack: _,
    } = update_params;

    let ips = IpPair::new(ipv4, ipv6).add_if_missing(ip);
    tracing::debug!("requested update for {ips:?}");

    if ips.is_empty() {
        return Err(UpdateError::NoIpForUpdate);
    }

    let Some(domain) = domain.as_deref() else {
        tracing::warn!("no domain set in query params, auto-detecting domain");
        let (domain, record) = single_record(ip, &state.records)?;

        return trigger_update(
            RecordUpdate {
                domain,
                record,
                ips,
                prefix,
            },
            &state,
        )
        .await;
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

    trigger_update(
        RecordUpdate {
            domain: &domain,
            record,
            ips,
            prefix,
        },
        &state,
    )
    .await
}

#[tracing::instrument(skip(state, update_params), level = "trace", ret(level = "info"))]
pub async fn update_records(
    State(state): State<crate::AppState<'static>>,
    ClientIp(ip): ClientIp,
    Query(update_params): Query<FritzBoxUpdateParams>,
) -> Result<&'static str, UpdateError> {
    info!("accepted update from {ip}");

    if update_params.is_empty() {
        update_from_ip(state, ip).await
    } else {
        update_from_query(state, ip, update_params).await
    }
}

#[tracing::instrument(skip_all, fields(domain = %record_update.domain), level = "trace", ret(level = "info"))]
async fn trigger_update(
    record_update: crate::nsupdate::RecordUpdate<'_>,
    state: &AppState<'static>,
) -> Result<&'static str, UpdateError> {
    let mut actions = record_update.actions()?.peekable();

    if actions.peek().is_none() {
        return Err(UpdateError::NoActions);
    }

    match crate::nsupdate::nsupdate(state.key_file, actions).await {
        Ok(status) if status.success() => {
            // Update saved data
            record_update.save_data(&mut *state.saved_data.write().await);

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
