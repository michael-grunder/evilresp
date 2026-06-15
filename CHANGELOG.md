# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Changed

- Scoped `DEBUG EVIL` configuration to each client connection so repeated
  reproducer runs against a still-running proxy start in non-evil mode.
- Canonicalized known unordered Redis replies before mutation by default, with
  `DEBUG EVIL CANONICALIZE <ALL|UNORDERED|NONE>` to control the behavior.
- Canonicalized unordered Redis set-operation replies from `SDIFF`, `SINTER`,
  and `SUNION` before mutation.
- Excluded `COMMAND` from default reply mutation so redis-cli can introspect
  server capabilities on connect.

### Fixed

- Rewrote upstream `MOVED` and `ASK` redirection endpoints to the corresponding
  local proxy listener before relaying them to clients.
- Changed `MONITOR` output to use a Redis-compatible `unix:evilresp:<id>`
  client address so monitor parsers accept evilresp command streams.
- Canonicalized unordered `EXEC` subreplies using the commands queued inside
  the transaction before deriving mutation hashes.
- Fixed same-proxy repeated reproducer runs by invalidating client connections
  from older reset epochs before they can consume deterministic command ids.
- Removed client connection identity from mutation RNG inputs so identical
  seeds, command indexes, commands, and upstream replies produce identical RESP
  mutations on every connection.
- Changed `DEBUG EVIL MODE RESET` to reset deterministic command ids without
  resetting connection ids.

### Added

- Added `DEBUG EVIL TOPOLOGY <probability>` for cluster-mode malicious `MOVED`
  and `ASK` redirection behavior independent from RESP mutation mode.
- Added local `MONITOR` support for streaming commands received from connected
  clients.
- Added per-connection input and output RESP protocol fingerprints exposed via
  `DEBUG PROTOCOL <IN|OUT> <BLAKE3|TLSH>`.
- Added deterministic protocol output regression coverage for repeated evil
  mode client sessions with identical seed, mode, probability, and input.
- Added `unix:/path/to/socket` endpoint support for proxying upstream AF_UNIX
  sockets and listening on local AF_UNIX sockets in standalone mode.
- Added `DEBUG EVIL MODE RESET` to disable evil mode and reset deterministic
  command ids.
- Added project-specific contributor and agent guidance in `AGENTS.md`.
- Added the initial RESP proxy server with standalone/cluster discovery,
  configurable human or JSON logging, deterministic evil modes, DEBUG EVIL
  runtime configuration commands, RESP2/RESP3 frame parsing, mutation-based
  replies, and optional repro JSONL output.
