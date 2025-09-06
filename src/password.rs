//! Make a password for use with webnsupdate
//!
//! You should call this command an give it's output to the app/script that will
//! update the DNS records
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use base64::prelude::*;
use miette::Context;
use miette::IntoDiagnostic;
use miette::Result;
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

    /// An application specific value
    #[arg(long, default_value = crate::DEFAULT_SALT)]
    salt: String,

    /// The file to write the password to
    password_file: Option<PathBuf>,
}

impl Mkpasswd {
    pub fn process(self, _args: &crate::Opts) -> Result<()> {
        mkpasswd(self)
    }
}

pub fn hash_basic_auth(user_pass: &[u8], salt: &str) -> Digest {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    context.update(user_pass);
    context.update(salt.as_bytes());
    context.finish()
}

pub fn hash_identity(username: &str, password: &str, salt: &str) -> Digest {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    context.update(username.as_bytes());
    context.update(b":");
    context.update(password.as_bytes());
    context.update(salt.as_bytes());
    context.finish()
}

pub fn mkpasswd(
    Mkpasswd {
        username,
        password,
        salt,
        password_file,
    }: Mkpasswd,
) -> miette::Result<()> {
    let hash = hash_identity(&username, &password, &salt);
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(hash.as_ref());
    let Some(path) = password_file.as_deref() else {
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
