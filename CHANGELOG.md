# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Changed

- Excluded `COMMAND` from default reply mutation so redis-cli can introspect
  server capabilities on connect.

### Added

- Added project-specific contributor and agent guidance in `AGENTS.md`.
- Added the initial RESP proxy server with standalone/cluster discovery,
  configurable human or JSON logging, deterministic evil modes, DEBUG EVIL
  runtime configuration commands, RESP2/RESP3 frame parsing, mutation-based
  replies, and optional repro JSONL output.
