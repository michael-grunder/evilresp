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
#[command(
    author,
    version,
    about,
    after_help = "\
Examples:
  Proxy a local Redis server (listen on 127.0.0.1:6380):
    evilresp --proxy localhost:6379

  Choose a listening address and enable trace logs:
    evilresp --proxy localhost:6379 --listen 127.0.0.1:6381 -vv

  Proxy between Unix sockets:
    evilresp --proxy unix:/tmp/redis.sock --listen unix:/tmp/evilresp.sock

  Record mutations and use JSON logs:
    evilresp --proxy localhost:6379 --repro-file repro.jsonl --log-mode json

Replies are unchanged by default. Enable mutations with DEBUG EVIL on the
same client connection that sends the commands to fuzz."
)]
pub struct Cli {
    /// Upstream Redis, Valkey, or DragonflyDB endpoint to proxy.
    ///
    /// Use host:port for TCP or unix:/path/to/socket for AF_UNIX.
    #[arg(long)]
    pub proxy: Endpoint,

    /// Local endpoint to listen on. Cluster mode supports TCP only and uses
    /// this port as the first local node port.
    #[arg(long, default_value = "127.0.0.1:6380")]
    pub listen: Endpoint,

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
pub enum Endpoint {
    Tcp(TcpEndpoint),
    Unix(PathBuf),
}

impl Endpoint {
    pub fn as_tcp(&self) -> Option<&TcpEndpoint> {
        match self {
            Self::Tcp(endpoint) => Some(endpoint),
            Self::Unix(_) => None,
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(endpoint) => endpoint.fmt(formatter),
            Self::Unix(path) => write!(formatter, "unix:{}", path.display()),
        }
    }
}

impl FromStr for Endpoint {
    type Err = AppError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(path) = value.strip_prefix("unix:") {
            if path.is_empty() {
                return Err(AppError::Proxy(
                    "unix endpoint path must not be empty".to_owned(),
                ));
            }
            return Ok(Self::Unix(PathBuf::from(path)));
        }

        Ok(Self::Tcp(value.parse()?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpEndpoint {
    pub host: String,
    pub port: u16,
}

impl TcpEndpoint {
    pub fn connect_addr(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl std::fmt::Display for TcpEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.connect_addr())
    }
}

impl FromStr for TcpEndpoint {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_endpoint() {
        let endpoint: Endpoint = "127.0.0.1:6379".parse().unwrap();

        assert_eq!(
            endpoint,
            Endpoint::Tcp(TcpEndpoint {
                host: "127.0.0.1".to_owned(),
                port: 6379
            })
        );
    }

    #[test]
    fn parses_unix_endpoint() {
        let endpoint: Endpoint = "unix:/tmp/redis.sock".parse().unwrap();

        assert_eq!(endpoint, Endpoint::Unix(PathBuf::from("/tmp/redis.sock")));
    }
}
