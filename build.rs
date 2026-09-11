use std::process::Command;

#[cfg(not(test))]
fn main() {
    // This path is never created: refresh metadata on every Cargo build,
    // including index-only changes, new untracked files, and a new UTC day.
    let out_dir = std::env::var("OUT_DIR").expect("Cargo sets OUT_DIR");
    println!("cargo:rerun-if-changed={out_dir}/build-metadata-always-rerun");

    let sha = output("git", &["rev-parse", "--verify", "HEAD"]);
    let status = output(
        "git",
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=normal",
            "--ignore-submodules=none",
        ],
    );
    let revision = revision(sha.as_deref(), status.as_deref());
    let date = output("date", &["-u", "+%Y-%m-%d"])
        .unwrap_or_else(|| "unknown".to_owned());
    let version = std::env::var("CARGO_PKG_VERSION")
        .expect("Cargo sets CARGO_PKG_VERSION");
    println!("cargo:rustc-env=EVILRESP_VERSION={version} ({revision} {date})");
}

fn output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_owned())
}

fn revision(sha: Option<&str>, status: Option<&str>) -> String {
    match (sha, status) {
        (Some(sha), Some(status)) => {
            let short: String = sha.chars().take(8).collect();
            let suffix = if status.is_empty() { "" } else { "-dirty" };
            format!("{short}{suffix}")
        }
        _ => "unknown".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn clean_revision_uses_eight_characters() {
        assert_eq!(revision(Some(SHA), Some("")), "01234567");
    }

    #[test]
    fn staged_unstaged_and_untracked_changes_are_dirty() {
        for status in ["M  src/cli.rs", " M README.md", "?? new-file"] {
            assert_eq!(revision(Some(SHA), Some(status)), "01234567-dirty");
        }
    }

    #[test]
    fn unavailable_git_metadata_is_unknown() {
        assert_eq!(revision(None, None), "unknown");
        assert_eq!(revision(Some(SHA), None), "unknown");
        assert_eq!(revision(None, Some("?? file")), "unknown");
    }

    #[test]
    fn failed_command_has_no_output() {
        assert_eq!(output("git", &["--evilresp-invalid-option"]), None);
    }
}
