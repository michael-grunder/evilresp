# Project Instructions

This file is the working agreement for agents and contributors changing this
repository. Keep it current as the project grows.

## Project Context

`evilresp` is a Rust 2024 project. The repository is intentionally small today,
so preserve room for clean growth instead of baking future assumptions into the
initial code.

Current top-level shape:

- `Cargo.toml` contains crate metadata and dependencies.
- `src/main.rs` is the current binary entry point.
- `rustfmt.toml` defines formatting preferences.
- `CHANGELOG.md` records user-visible or project-relevant changes.

## Core Principles

- Prefer clear, modular code over large files or broad catch-all modules.
- Prefer generic, reusable behavior over duplication unless a measured
  performance concern justifies specialization.
- Prefer defensive programming. Handle fallible operations explicitly, and do
  not ignore return values or errors unless there is a documented reason.
- Keep feature work cohesive. Do not scatter feature-specific branches across
  unrelated modules when a small redesign would keep the architecture cleaner.
- Make invalid states hard to represent with Rust types when doing so stays
  readable.
- Keep public behavior and internal contracts documented close to the code that
  owns them.

## Rust Conventions

- Use the Rust 2024 edition conventions already configured in `Cargo.toml`.
- Run `cargo fmt` before finishing any code change.
- Run `cargo clippy --all-targets --all-features -- -D warnings` before
  finishing any code change, and fix warnings instead of suppressing them.
- Run `cargo test --all-targets --all-features` before finishing any code
  change.
- Keep `main.rs` thin as functionality grows. Move parsing, protocol logic,
  I/O, and reusable behavior into focused modules.
- Prefer `Result`-returning functions for fallible workflows. Use `panic!` only
  for programmer errors or impossible states, not normal runtime failures.
- Avoid `unwrap()` and `expect()` in production code unless the invariant is
  local, obvious, and explained by context. They are acceptable in tests when
  they keep assertions clear.
- Prefer borrowing over cloning. Clone only when ownership boundaries require it
  or when it materially improves clarity.
- Keep dependencies intentional. Before adding a crate, confirm that it solves a
  real problem, is maintained, and is appropriate for the project's size.

## Architecture Guidelines

- Introduce modules around responsibilities, not around incidental categories.
  Good boundaries usually follow parsing, protocol/model types, execution, I/O,
  configuration, and error handling.
- Keep side effects at the edges. Core logic should be easy to unit test without
  filesystem, network, process, or terminal dependencies.
- Prefer small data types that express domain meaning over passing raw strings,
  integers, or tuples through multiple layers.
- Keep APIs narrow. Expose only what other modules need, and avoid making
  internals public for test convenience.
- When a feature changes existing control flow, update the surrounding design so
  the new behavior fits naturally.

## Error Handling

- Preserve useful context on errors at module boundaries.
- Return structured errors for library-style code. Human-friendly formatting can
  happen at the binary/UI boundary.
- Validate external input early, then pass validated types deeper into the
  system.
- Treat partial writes, short reads, parse failures, invalid encodings, and
  interrupted I/O as normal failure modes unless the caller proves otherwise.

## Testing Expectations

- Add tests with behavior changes. Cover both the success path and meaningful
  failure cases.
- Prefer unit tests for pure logic and integration tests for CLI or process
  behavior.
- Avoid tests that depend on wall-clock timing, network availability, global
  machine state, or test order.
- Keep fixtures small and specific. If fixtures grow, place them under a clear
  test-only directory and document why they exist.
- When fixing a bug, add a regression test that fails without the fix whenever
  practical.

## Documentation And Changelog

- Keep `README.md` updated when a change affects how users install, run,
  configure, or understand the project. Create it when there is user-facing
  behavior worth documenting.
- Keep `CHANGELOG.md` updated for every meaningful change.
- Add new changelog entries under `## Unreleased`.
- Within each changelog version, use Keep a Changelog-style sections as
  applicable: `### Added`, `### Changed`, `### Deprecated`, `### Removed`,
  `### Fixed`, and `### Security`.
- Documentation should describe actual behavior, commands, assumptions, and
  limitations. Avoid aspirational claims that the code does not yet satisfy.

## Git And Workspace Hygiene

- Do not revert, overwrite, or clean up unrelated user changes.
- Before editing files, inspect the relevant current contents.
- Keep changes scoped to the requested task.
- Do not commit unless the user explicitly asks for a commit.
- Avoid generated churn. Do not reformat unrelated files or rewrite lockfiles
  unless the task requires it.

## Required Finish Checklist

Before considering a code change complete:

1. Run `cargo fmt`.
2. Run `cargo clippy --all-targets --all-features -- -D warnings`.
3. Run `cargo test --all-targets --all-features`.
4. Update `CHANGELOG.md`.
5. Update `README.md` if user-facing behavior or setup changed.
6. Summarize what changed and mention any commands that could not be run.
