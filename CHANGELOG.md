# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Changed

- Excluded `COMMAND` from default reply mutation so redis-cli can introspect
  server capabilities on connect.

### Fixed

- Fixed `DEBUG EVIL MODE RESET` so the active connection also resets to
  connection id zero, making repeated same-seed client runs produce identical
  mutations.

### Added

- Added `unix:/path/to/socket` endpoint support for proxying upstream AF_UNIX
  sockets and listening on local AF_UNIX sockets in standalone mode.
- Added `DEBUG EVIL MODE RESET` to disable evil mode and reset deterministic
  incrementing state such as connection ids.
- Added project-specific contributor and agent guidance in `AGENTS.md`.
- Added the initial RESP proxy server with standalone/cluster discovery,
  configurable human or JSON logging, deterministic evil modes, DEBUG EVIL
  runtime configuration commands, RESP2/RESP3 frame parsing, mutation-based
  replies, and optional repro JSONL output.
