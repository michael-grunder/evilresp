use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Write};
use std::sync::Mutex;

use tracing::{Level, Metadata, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::{self, MakeWriter, writer::BoxMakeWriter};
use tracing_subscriber::prelude::*;

use crate::cli::{LogMode, LogOutput};
use crate::error::{AppError, AppResult};

pub fn init(
    mode: LogMode,
    verbosity: u8,
    output: Option<&LogOutput>,
) -> AppResult<()> {
    let default_level = match verbosity {
        0 => "evilresp=info",
        1 => "evilresp=debug",
        _ => "evilresp=trace",
    };
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default_level))
        .expect("static tracing filter must be valid");
    subscriber(mode, filter, output)?
        .try_init()
        .map_err(|error| {
            AppError::Startup(format!("initializing logging: {error}"))
        })
}

fn subscriber(
    mode: LogMode,
    filter: EnvFilter,
    output: Option<&LogOutput>,
) -> AppResult<Box<dyn Subscriber + Send + Sync>> {
    let output = output.unwrap_or(&LogOutput::Stderr);
    let writer = open_writer(output)?;
    let ansi = *output == LogOutput::Stderr && io::stderr().is_terminal();
    let registry = tracing_subscriber::registry().with(filter);

    Ok(match mode {
        LogMode::Human => Box::new(
            registry.with(
                fmt::layer()
                    .compact()
                    .with_ansi(ansi)
                    .with_target(false)
                    .with_writer(writer),
            ),
        ),
        LogMode::Json => {
            Box::new(registry.with(
                fmt::layer().json().flatten_event(true).with_writer(writer),
            ))
        }
    })
}

fn open_writer(output: &LogOutput) -> AppResult<BoxMakeWriter> {
    Ok(match output {
        LogOutput::Stderr => BoxMakeWriter::new(io::stderr),
        LogOutput::File(path) => {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|error| {
                    AppError::Startup(format!(
                        "opening log file {}: {error}",
                        path.display()
                    ))
                })?;
            BoxMakeWriter::new(Mutex::new(file))
        }
        LogOutput::Syslog => {
            // openlog retains the identifier pointer; this literal is static.
            unsafe {
                libc::openlog(
                    c"evilresp".as_ptr(),
                    libc::LOG_PID | libc::LOG_NDELAY,
                    libc::LOG_DAEMON,
                );
            }
            BoxMakeWriter::new(Syslog)
        }
    })
}

struct Syslog;

impl MakeWriter<'_> for Syslog {
    type Writer = SyslogRecord;

    fn make_writer(&self) -> Self::Writer {
        SyslogRecord {
            priority: libc::LOG_INFO,
            bytes: Vec::new(),
        }
    }

    fn make_writer_for(&self, metadata: &Metadata<'_>) -> Self::Writer {
        SyslogRecord {
            priority: syslog_priority(metadata.level()),
            bytes: Vec::new(),
        }
    }
}

fn syslog_priority(level: &Level) -> libc::c_int {
    match *level {
        Level::ERROR => libc::LOG_ERR,
        Level::WARN => libc::LOG_WARNING,
        Level::INFO => libc::LOG_INFO,
        Level::DEBUG | Level::TRACE => libc::LOG_DEBUG,
    }
}

struct SyslogRecord {
    priority: libc::c_int,
    bytes: Vec<u8>,
}

impl Write for SyslogRecord {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn syslog_message(bytes: &[u8]) -> CString {
    let message = String::from_utf8_lossy(bytes)
        .trim_end()
        .replace('\0', "\\0");
    // Interior NULs were escaped above.
    CString::new(message).expect("syslog message contains no NULs")
}

impl Drop for SyslogRecord {
    fn drop(&mut self) {
        if !self.bytes.is_empty() {
            let message = syslog_message(&self.bytes);
            // Use a constant format string: log text can contain percent signs.
            // Both strings are NUL-terminated and live through the call.
            unsafe {
                libc::syslog(self.priority, c"%s".as_ptr(), message.as_ptr());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_append_complete_human_and_json_events_without_ansi() {
        let path = std::env::temp_dir()
            .join(format!("evilresp-log-{}.log", std::process::id()));
        std::fs::write(&path, b"existing\n").unwrap();
        let output = LogOutput::File(path.clone());
        for mode in [LogMode::Human, LogMode::Json] {
            let subscriber = subscriber(
                mode,
                EnvFilter::new("evilresp=info"),
                Some(&output),
            )
            .unwrap();
            tracing::subscriber::with_default(subscriber, || {
                tracing::info!(answer = 42, "log output test");
            });
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "existing");
        assert!(lines[1].contains("log output test"));
        assert!(lines[1].contains("answer=42"));
        assert!(!text.contains('\x1b'));
        let json: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(json["message"], "log output test");
        assert_eq!(json["answer"], 42);
        assert_eq!(json["level"], "INFO");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn log_file_open_errors_include_the_path() {
        let directory = std::env::temp_dir();
        let error = match open_writer(&LogOutput::File(directory.clone())) {
            Ok(_) => panic!("cannot append logs to a directory"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("opening log file"), "{error}");
        assert!(error.contains(&directory.display().to_string()), "{error}");
    }

    #[test]
    fn syslog_preserves_severity_and_escapes_nuls_without_treating_text_as_a_format()
     {
        for (level, expected) in [
            (Level::ERROR, libc::LOG_ERR),
            (Level::WARN, libc::LOG_WARNING),
            (Level::INFO, libc::LOG_INFO),
            (Level::DEBUG, libc::LOG_DEBUG),
            (Level::TRACE, libc::LOG_DEBUG),
        ] {
            assert_eq!(syslog_priority(&level), expected);
        }
        assert_eq!(
            syslog_message(b"100% %s %n\0tail\n").to_bytes(),
            b"100% %s %n\\0tail"
        );
    }
}
