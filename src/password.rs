//! Make a password for use with webnsupdate
//!
//! You should call this command an give it's output to the app/script that will update the DNS
//! records
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use base64::prelude::*;
use miette::{Context, IntoDiagnostic, Result};
use ring::digest::Digest;

/// Create a password file
///
/// If `--password-file` is provided, the password is written to that file
#[derive(Debug, clap::Args)]
pub struct Mkpasswd {
    /// The username
    username: String,

    /// The password
    password: String,
}

impl Mkpasswd {
    pub fn process(self, args: &crate::Opts) -> Result<()> {
        mkpasswd(self, args.password_file.as_deref(), &args.salt)
    }
}

pub fn hash_identity(username: &str, password: &str, salt: &str) -> Digest {
    let mut data = Vec::with_capacity(username.len() + password.len() + salt.len() + 1);
    write!(data, "{username}:{password}{salt}").unwrap();
    ring::digest::digest(&ring::digest::SHA256, &data)
}

pub fn mkpasswd(
    Mkpasswd { username, password }: Mkpasswd,
    password_file: Option<&Path>,
    salt: &str,
) -> miette::Result<()> {
    let hash = hash_identity(&username, &password, salt);
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(hash.as_ref());
    let Some(path) = password_file else {
        println!("{encoded}");
        return Ok(());
    };
    let err = || format!("trying to save password hash to {}", path.display());
    std::fs::File::options()
        .mode(0o600)
        .create_new(true)
        .open(path)
        .into_diagnostic()
        .wrap_err_with(err)?
        .write_all(encoded.as_bytes())
        .into_diagnostic()
        .wrap_err_with(err)?;

    Ok(())
}
