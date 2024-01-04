mod commands;
mod nomad;
mod opts;
use anyhow::{Error, Result};
use clap::{FromArgMatches, Parser};
use commands::deploy::DeployCommand;

/// Returns build information, similar to: 0.1.0 (2be4034 2022-03-31).
const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("VERGEN_GIT_SHA"),
    " ",
    env!("VERGEN_GIT_COMMIT_DATE"),
    ")"
);

#[derive(Parser)]
#[clap(author, version = VERSION, about, long_about = None)]
#[clap(propagate_version = true)]
enum Cli {
    /// Publish an application to the registry and deploy to Nomad.
    Deploy(DeployCommand),
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut app = Cli::clap();
    // Plugin should always be invoked from Spin so set binary name accordingly
    app.set_bin_name("spin nomad");
    let matches = app.get_matches();
    let cli = Cli::from_arg_matches(&matches)?;

    match cli {
        Cli::Deploy(cmd) => cmd.run().await,
    }
}
