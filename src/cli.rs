use std::path::PathBuf;
use std::str::FromStr;

use clap::Parser;

use crate::error::AppError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum LogMode {
    Human,
    Json,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogOutput {
    Stderr,
    Syslog,
    File(PathBuf),
}

impl FromStr for LogOutput {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "" => {
                Err("log output must be a path, stderr, or syslog".to_owned())
            }
            "stderr" => Ok(Self::Stderr),
            "syslog" => Ok(Self::Syslog),
            path => Ok(Self::File(path.into())),
        }
    }
}

impl std::fmt::Display for LogOutput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stderr => formatter.write_str("stderr (inherited)"),
            Self::Syslog => formatter
                .write_str("syslog (identifier: evilresp, facility: daemon)"),
            Self::File(path) => path.display().fmt(formatter),
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    author,
    version = env!("EVILRESP_VERSION"),
    about,
    after_help = "\
Examples:
  Proxy a local Redis server (listen on 127.0.0.1:6380):
    evilresp --proxy localhost:6379

  Choose a listening address and enable trace logs:
    evilresp --proxy localhost:6379 --listen 127.0.0.1:6381 -vv

  Proxy between Unix sockets:
    evilresp --proxy unix:/tmp/redis.sock --listen unix:/tmp/evilresp.sock

  Start in the background; stop through any proxy listener:
    evilresp --proxy localhost:6379 --daemonize
    redis-cli -p 6380 DEBUG SHUTDOWN NOSAVE

  Run in the background with syslog or an append-only log file:
    evilresp --proxy localhost:6379 --daemonize --logfile syslog
    evilresp --proxy localhost:6379 --daemonize --logfile ./evilresp.log

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

    /// Run in the background after reporting startup success or failure.
    #[arg(long)]
    pub daemonize: bool,

    #[arg(long, hide = true, requires = "daemonize")]
    pub(crate) daemon_child: bool,

    /// Append deterministic mutation records as JSON lines.
    #[arg(long)]
    pub repro_file: Option<PathBuf>,

    /// Log format.
    #[arg(long, value_enum, default_value_t = LogMode::Human)]
    pub log_mode: LogMode,

    /// Log destination: a file path (append), stderr, or syslog.
    /// Defaults to stderr in foreground mode; discarded when daemonized.
    #[arg(long = "logfile", value_name = "PATH|stderr|syslog")]
    pub log_output: Option<LogOutput>,

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

    mod build_metadata {
        include!("../build.rs");
    }

    #[test]
    fn logfile_accepts_reserved_names_and_paths() {
        let args = ["evilresp", "--proxy", "localhost:6379"];
        assert!(Cli::try_parse_from(args).unwrap().log_output.is_none());
        for (value, expected) in [
            ("stderr", LogOutput::Stderr),
            ("syslog", LogOutput::Syslog),
            ("/tmp/proxy logs", LogOutput::File("/tmp/proxy logs".into())),
            ("./syslog", LogOutput::File("./syslog".into())),
            ("./stderr", LogOutput::File("./stderr".into())),
        ] {
            let cli = Cli::try_parse_from(
                args.into_iter().chain(["--logfile", value]),
            )
            .unwrap();
            assert_eq!(cli.log_output, Some(expected));
        }
        for invalid in [vec!["--logfile"], vec!["--logfile", ""]] {
            assert!(
                Cli::try_parse_from(args.into_iter().chain(invalid)).is_err()
            );
        }
    }

    #[test]
    fn daemonize_is_opt_in_and_takes_no_value() {
        let args = ["evilresp", "--proxy", "localhost:6379"];
        assert!(!Cli::try_parse_from(args).unwrap().daemonize);
        assert!(
            Cli::try_parse_from(args.into_iter().chain(["--daemonize"]))
                .unwrap()
                .daemonize
        );
        assert!(
            Cli::try_parse_from(args.into_iter().chain(["--daemonize=no"]))
                .is_err()
        );
    }

    #[test]
    fn version_flags_print_build_metadata_without_proxy() {
        for flag in ["-V", "--version"] {
            let error = Cli::try_parse_from(["evilresp", flag]).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
            assert_eq!(
                error.to_string(),
                format!("evilresp {}\n", env!("EVILRESP_VERSION"))
            );
        }
    }

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
