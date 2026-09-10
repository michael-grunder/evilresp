#![warn(clippy::all, clippy::nursery, clippy::pedantic)]
use clap::Parser;
use evilresp::cli::Cli;
use evilresp::error::AppResult;

#[tokio::main]
async fn main() -> AppResult<()> {
    let cli = Cli::parse();
    evilresp::logging::init(cli.log_mode, cli.verbose);
    evilresp::proxy::run(cli).await
}
