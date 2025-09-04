//! --- Default Values (sadly serde doesn't have a way to specify a constant as
//! a default value) ---

pub fn ttl() -> humantime::Duration {
    crate::DEFAULT_TTL.into()
}

pub fn salt() -> Box<str> {
    crate::DEFAULT_SALT.into()
}

pub fn address() -> std::net::SocketAddr {
    std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 5353)
}

pub fn ip_source() -> axum_client_ip::ClientIpSource {
    axum_client_ip::ClientIpSource::RightmostXForwardedFor
}

pub fn ip_type() -> super::IpType {
    super::IpType::Both
}
