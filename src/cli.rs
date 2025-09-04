use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;
use clap_verbosity_flag::Verbosity;

#[derive(Debug, Parser)]
pub struct Opts {
    #[command(flatten)]
    pub verbosity: Verbosity<clap_verbosity_flag::InfoLevel>,

    /// Data directory
    #[arg(long, env, default_value = ".")]
    pub data_dir: PathBuf,

    /// Allow not setting a password
    #[arg(long)]
    pub insecure: bool,

    #[clap(flatten)]
    pub config_or_command: ConfigOrCommand,
}

#[derive(clap::Args, Debug)]
#[group(multiple = false)]
pub struct ConfigOrCommand {
    /// Path to the configuration file
    #[arg(long, short)]
    pub config: Option<PathBuf>,

    #[clap(subcommand)]
    pub subcommand: Option<Cmd>,
}

impl ConfigOrCommand {
    pub fn take(&mut self) -> (Option<PathBuf>, Option<Cmd>) {
        (self.config.take(), self.subcommand.take())
    }
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    Mkpasswd(crate::password::Mkpasswd),
    /// Verify the configuration file
    Verify {
        /// Path to the configuration file
        config: PathBuf,
    },
}

impl Cmd {
    pub fn process(self, args: &Opts) -> miette::Result<()> {
        match self {
            Cmd::Mkpasswd(mkpasswd) => mkpasswd.process(args),
            Cmd::Verify { config } => crate::config::Config::load(&config)? // load config
                .verified() // verify config
                .map(drop),
        }
    }
}
