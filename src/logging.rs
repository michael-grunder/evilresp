use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

use crate::cli::LogMode;

pub fn init(mode: LogMode, verbosity: u8) {
    let default_level = match verbosity {
        0 => "evilresp=info",
        1 => "evilresp=debug",
        _ => "evilresp=trace",
    };
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default_level))
        .expect("static tracing filter must be valid");

    match mode {
        LogMode::Human => {
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    fmt::layer()
                        .compact()
                        .with_ansi(true)
                        .with_target(false)
                        .with_writer(std::io::stderr),
                )
                .init();
        }
        LogMode::Json => {
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    fmt::layer()
                        .json()
                        .flatten_event(true)
                        .with_writer(std::io::stderr),
                )
                .init();
        }
    }
}
