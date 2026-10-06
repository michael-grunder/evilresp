#![warn(clippy::all, clippy::nursery, clippy::pedantic)]
use std::process::ExitCode;

use clap::Parser;

use evilresp::cli::Cli;

fn main() -> ExitCode {
    match evilresp::daemon::run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("evilresp: {error}");
            ExitCode::FAILURE
        }
    }
}
