//! Re-exec before starting Tokio, and report readiness over a private pipe.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::process::{Command, Stdio};

use crate::cli::{Cli, LogOutput};
use crate::error::{AppError, AppResult};

unsafe extern "C" {
    fn setsid() -> i32;
    fn dup2(oldfd: i32, newfd: i32) -> i32;
}

pub fn run(cli: Cli) -> AppResult<()> {
    if cli.daemonize && !cli.daemon_child {
        return launch(&cli);
    }
    let child = cli.daemon_child;
    let result = (|| {
        if child {
            // This is a freshly exec'd process, before any runtime threads.
            if unsafe { setsid() } == -1 {
                return Err(io::Error::last_os_error().into());
            }
        }
        crate::logging::init(
            cli.log_mode,
            cli.verbose,
            cli.log_output.as_ref(),
        )?;
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(crate::proxy::run(cli))
    })();
    if child && let Err(error) = &result {
        let _ = report(Err(error.to_string()));
    }
    result
}

fn launch(cli: &Cli) -> AppResult<()> {
    let mut child = Command::new(std::env::current_exe()?)
        .arg("--daemon-child")
        .args(std::env::args_os().skip(1))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(if cli.log_output == Some(LogOutput::Stderr) {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .spawn()?;
    let result = (|| {
        let mut line = String::new();
        // stdout was explicitly piped above.
        BufReader::new(child.stdout.take().expect("startup pipe"))
            .read_line(&mut line)?;
        let status: Result<Vec<String>, String> = serde_json::from_str(&line)
            .map_err(|error| {
            AppError::Startup(format!(
                "daemon exited without a valid startup report: {error}"
            ))
        })?;
        status.map_err(AppError::Startup)
    })();
    match result {
        Ok(mappings) => {
            println!("evilresp running in background (PID {})", child.id());
            for mapping in mappings {
                println!("  {mapping}");
            }
            let destination = cli.log_output.as_ref().map_or_else(
                || "discarded (/dev/null)".to_owned(),
                ToString::to_string,
            );
            println!("  Logs: {destination}");
            Ok(())
        }
        Err(error) => {
            // Also stop a child whose startup report could not be delivered.
            let _ = child.kill();
            let _ = child.wait();
            Err(error)
        }
    }
}

fn report(status: Result<Vec<String>, String>) -> AppResult<()> {
    write_report(io::stdout().lock(), status)
}

fn write_report(
    mut writer: impl Write,
    status: Result<Vec<String>, String>,
) -> AppResult<()> {
    serde_json::to_writer(&mut writer, &status)?;
    writeln!(writer)?;
    writer.flush()?;
    Ok(())
}

pub(crate) fn ready(mappings: Vec<String>) -> AppResult<()> {
    let null = File::options().write(true).open("/dev/null")?;
    let pipe = File::from(io::stdout().as_fd().try_clone_to_owned()?);
    // No further output may keep the launcher's pipe open or reach its terminal.
    // dup2 only replaces this process's stdout with an already open descriptor.
    if unsafe { dup2(null.as_raw_fd(), 1) } == -1 {
        return Err(io::Error::last_os_error().into());
    }
    write_report(pipe, Ok(mappings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_reports_preserve_mappings_errors_and_pipe_failures() {
        for status in [
            Ok(vec!["127.0.0.1:6380 -> localhost:6379".to_owned()]),
            Err("binding unix:/tmp/proxy\nname: address in use".to_owned()),
        ] {
            let mut bytes = Vec::new();
            write_report(&mut bytes, status.clone()).unwrap();
            assert_eq!(bytes.iter().filter(|&&b| b == b'\n').count(), 1);
            let decoded: Result<Vec<String>, String> =
                serde_json::from_slice(&bytes).unwrap();
            assert_eq!(decoded, status);
        }
        // A lost startup channel must prevent successful daemon startup.
        assert!(write_report(&mut [0_u8; 0][..], Ok(Vec::new())).is_err());
    }
}
