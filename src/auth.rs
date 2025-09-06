use axum::http::HeaderValue;
use axum::http::Request;
use axum::http::Response;
use axum::http::header;
use axum::http::status::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tower_http::validate_request::ValidateRequestHeaderLayer;
use tracing::trace;
use tracing::warn;

use crate::password;

pub fn layer<'a, ResBody>(
    user_pass_hash: &'a [u8],
    salt: &'a str,
) -> ValidateRequestHeaderLayer<Basic<'a, ResBody>> {
    ValidateRequestHeaderLayer::custom(Basic::new(user_pass_hash, salt))
}

#[derive(Copy)]
pub struct Basic<'a, ResBody> {
    pass: &'a [u8],
    salt: &'a str,
    _ty: std::marker::PhantomData<fn() -> ResBody>,
}

impl<ResBody> std::fmt::Debug for Basic<'_, ResBody> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicAuth")
            .field("pass", &self.pass)
            .field("salt", &self.salt)
            .field("_ty", &self._ty)
            .finish()
    }
}

impl<ResBody> Clone for Basic<'_, ResBody> {
    fn clone(&self) -> Self {
        Self {
            pass: self.pass,
            salt: self.salt,
            _ty: std::marker::PhantomData,
        }
    }
}

impl<'a, ResBody> Basic<'a, ResBody> {
    pub fn new(pass: &'a [u8], salt: &'a str) -> Self {
        Self {
            pass,
            salt,
            _ty: std::marker::PhantomData,
        }
    }

    fn check_headers(&self, headers: &axum::http::HeaderMap<HeaderValue>) -> bool {
        let Some(auth) = headers.get(header::AUTHORIZATION) else {
            return false;
        };

        // Poor man's split once: https://doc.rust-lang.org/std/primitive.slice.html#method.split_once
        let Some(index) = auth.as_bytes().iter().position(|&c| c == b' ') else {
            return false;
        };
        let user_pass = &auth.as_bytes()[index + 1..];

        match base64::engine::general_purpose::URL_SAFE.decode(user_pass) {
            Ok(user_pass) => {
                let hashed = password::hash_basic_auth(&user_pass, self.salt);
                if hashed.as_ref() == self.pass {
                    return true;
                }
                warn!("rejected update");
                trace!(
                    "mismatched hashes:\nprovided: {}\nstored:   {}",
                    URL_SAFE_NO_PAD.encode(hashed.as_ref()),
                    URL_SAFE_NO_PAD.encode(self.pass),
                );
                false
            }
            Err(err) => {
                warn!("received invalid base64 when decoding Basic header: {err}");
                false
            }
        }
    }
}

impl<B, ResBody> tower_http::validate_request::ValidateRequest<B> for Basic<'_, ResBody>
where
    ResBody: Default,
{
    type ResponseBody = ResBody;

    fn validate(&mut self, request: &mut Request<B>) -> Result<(), Response<Self::ResponseBody>> {
        if self.check_headers(request.headers()) {
            return Ok(());
        }

        let mut res = Response::new(ResBody::default());
        *res.status_mut() = StatusCode::UNAUTHORIZED;
        res.headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic"));
        Err(res)
    }
}
