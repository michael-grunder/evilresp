use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use clap::Parser;

use crate::error::AppError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum LogMode {
    Human,
    Json,
}

#[derive(Debug, Parser)]
#[command(author, version, about)]
pub struct Cli {
    /// Upstream Redis, Valkey, or DragonflyDB endpoint to proxy.
    #[arg(long)]
    pub proxy: Endpoint,

    /// Local address to listen on. Cluster mode uses this port as the first
    /// local node port.
    #[arg(long, default_value = "127.0.0.1:6380")]
    pub listen: SocketAddr,

    /// Append deterministic mutation records as JSON lines.
    #[arg(long)]
    pub repro_file: Option<PathBuf>,

    /// Log format.
    #[arg(long, value_enum, default_value_t = LogMode::Human)]
    pub log_mode: LogMode,

    /// Increase logging verbosity. Repeat for trace logs.
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn connect_addr(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.connect_addr())
    }
}

impl FromStr for Endpoint {
    type Err = AppError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (host, port) = if let Some(rest) = value.strip_prefix('[') {
            let Some((host, rest)) = rest.split_once("]:") else {
                return Err(AppError::Proxy(format!(
                    "endpoint {value:?} must be host:port"
                )));
            };
            (host.to_owned(), parse_port(rest)?)
        } else {
            let Some((host, port)) = value.rsplit_once(':') else {
                return Err(AppError::Proxy(format!(
                    "endpoint {value:?} must be host:port"
                )));
            };
            (host.to_owned(), parse_port(port)?)
        };

        if host.is_empty() {
            return Err(AppError::Proxy(
                "endpoint host must not be empty".to_owned(),
            ));
        }

        Ok(Self { host, port })
    }
}

fn parse_port(value: &str) -> Result<u16, AppError> {
    value.parse::<u16>().map_err(|error| {
        AppError::Proxy(format!("invalid endpoint port: {error}"))
    })
}
