# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added

- Rewrote `CLUSTER SHARDS` and `CLUSTER NODES` replies to the local proxy
  listeners so clients that discover the cluster with either command (Relay
  uses `CLUSTER SHARDS`) connect back through evilresp instead of the
  upstream nodes. Nodes without a local listener are removed from the reply.
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

### Changed

- Limited incoming RESP frames to 64 MiB and 128 nesting levels, with
  incremental reads instead of allocation from advertised lengths.
- Documented build instructions, protocol limitations, probability and filter
  semantics, reset behavior, and reproduction requirements. Corrected the
  contributor guide's mutation seed hash description to SHA-256.
- Scoped `DEBUG EVIL` configuration to each client connection so repeated
  reproducer runs against a still-running proxy start in non-evil mode.
- Canonicalized known unordered Redis replies before mutation by default, with
  `DEBUG EVIL CANONICALIZE <ALL|UNORDERED|NONE>` to control the behavior.
- Canonicalized unordered Redis set-operation replies from `SDIFF`, `SINTER`,
  and `SUNION` before mutation.
- Excluded `COMMAND` from default reply mutation so redis-cli can introspect
  server capabilities on connect.

### Fixed

- Made rejected `DEBUG EVIL MODE` updates leave the active configuration
  unchanged; `SEED` and `STATUS` now reject extra arguments.
- Rejected invalid negative RESP lengths and oversized aggregates without
  arithmetic overflow or allocation panics. Incomplete inline commands now
  fail during frame reading.
- Prevented malformed command arrays from becoming local commands when
  non-string arguments were silently removed.
- Preserved rewritten cluster redirection targets through RESP mutation,
  including at probability zero. Unmapped targets now produce a local error
  instead of exposing an upstream endpoint.
- Tracked transaction commands from upstream acknowledgements so rejected
  commands do not misalign `EXEC` reply canonicalization; isolated this logic
  in its own module.
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
