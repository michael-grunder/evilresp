# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added

- Added focused `DEBUG EVIL TOPOLOGY REDIRECT` faults with independent
  probability, MOVED/ASK selection, wrong-owner/self/replica/next/random or
  explicit endpoint targets, correct/wrong/wild/fixed slots, binary key
  argument selection, and injection before forwarding or after execution.
  `UNTIL` bounds injection by the shared command index for deterministic
  bounce/recovery experiments across configured connections. Added
  `TOPOLOGY OFF`; probability-only commands retain their legacy algorithm.
- Added topology configuration details to `STATUS` and
  `topology_redirect_before`/`topology_redirect_after` repro mutation kinds.
  Before-forwarding redirects have null upstream response fields.
- Added one INFO statistics summary per second across all listeners, with
  total accepted and currently active clients, successful `DEBUG EVIL`
  configuration commands, status reads, rejections, resets, and selections of
  each mode. Monitoring totals survive `MODE RESET`.
- Added independent `DEBUG EVIL TRANSPORT` plans for truncation followed by
  write-side shutdown, up to 16 extra replies, explicit or seeded chunk
  boundaries, and per-reply probability. Plans honor filters and bootstrap
  bypasses, are per connection, and survive mode changes and reset.
- Added versioned `delivery_plan`, `planned_wire_bytes_hex`, and
  `delivery_outcome` fields to repro records, including accepted byte counts,
  hashes, completed chunks, shutdown results, and I/O failure stage/kind.
  Transport-only faults and ordinary reply write failures produce records.
  Existing mutated-response fields retain the pre-transport response.

- Added `DEBUG EVIL GENERATOR` with per-connection `PROTOCOL RESP2|RESP3`,
  `CORPUS BOUNDARY|RANDOM`, and `VIOLATIONS OFF|ON` controls, reported by
  `STATUS` and preserved by mode changes and reset. Partial updates retain
  omitted options; invalid or duplicate options leave configuration unchanged.
- Expanded generated replies and scalar mutations with numeric extremes,
  binary payloads through 4097 bytes, empty/singleton aggregates, RESP2 null
  forms, and all ordinary RESP3 types. Deliberate malformed numeric/verbatim
  contents and standalone push/attribute frames require violations opt-in.

- Added `DEBUG EVIL FRAMING <AUTO|OFF|LENGTH>` with independent probability,
  root or nested target paths, and shorter, longer, negative, boundary, and
  overflow length faults. Framing-only mutation works at value probability
  zero; explicit framing takes priority for the `MUTATIONS ONE` slot.
- Added `length` details to repro mutation entries for length faults, recording
  the applied corruption kind and original/replacement decimal strings while
  retaining existing `path` and `kind` fields. Other mutation entries retain
  their existing shape.
- Added `DEBUG EVIL STRATEGY <PRESERVE|REPLACE>` to choose scalar mutation
  within original reply containers or whole-frame replacement, and
  `DEBUG EVIL MUTATIONS <ONE|MANY>` to select one eligible frame per reply
  without an additional length fault or mutate multiple frames. Both
  settings are per connection, reported by `STATUS`, and preserved by reset.
- Added one-to-one cluster replica listeners after the existing primary port
  assignments. `CLUSTER SLOTS`, `CLUSTER SHARDS`, `CLUSTER NODES`, and
  redirections use the same primary and replica mapping, preserving node IDs
  and replica relationships. Topology rewriting also matches discovered node
  IDs when replies advertise alternative addresses.
- Added the complete parsed argument array to debug logs for rejected
  `DEBUG PROTOCOL` commands, visible with `-v` or `-vv`. Error replies and
  warnings now identify invalid arguments and valid choices, missing arguments,
  or the first extra argument.
- Added CLI help examples for TCP and Unix sockets, custom listening addresses,
  verbose logging, and mutation recording.
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

- Moved individual evil configuration status logs from INFO to DEBUG (`-v`)
  and stopped logging `STATUS` reads as configuration changes.
- Unified reply delivery after RESP/topology processing. Transport uses a
  separate seeded RNG; chunk plans do not guarantee client read boundaries.
  Truncation and delivery errors stop processing buffered commands.
- Append repro records after delivery to capture partial failures, before
  processing the next command. Pending or cancelled delivery has no completed
  record; observed OS failures are separate from deterministic plans.

- Defaulted generation to RESP2 with a weighted boundary corpus and
  violations disabled. Generated trees stay within the selected protocol
  unless violations are enabled; protocol selection does not translate
  upstream replies. Generated subtrees are limited to three levels, four
  elements or pairs per aggregate, and 4097 bytes per blob payload.
- Kept mutated doubles, big numbers, and verbatim formats valid by default,
  including overflow mutations. Length faults remain independently controlled
  by `FRAMING`. The expanded generator changes seeded `RANDOM`, `MUTATE`,
  and `OVERFLOW` output; reproduce with the same build and settings.

- Encoded selected length faults directly from the typed frame tree, keeping
  actual bodies and other headers intact without allocating advertised sizes.
  Default `FRAMING AUTO` preserves the previous root-only wire behavior;
  framing settings are per connection and survive mode changes and reset.
- Defaulted RESP value mutation to `PRESERVE`, allowing `OVERFLOW` to reach
  values inside arrays, maps, and sets at full probability. `MANY` retains
  the separate root length-corruption attempt. Selected value mutations
  always change their target, and replacement subtrees are no longer mutated
  again. These changes alter seeded `MUTATE` and `OVERFLOW` output; reproduce
  cases with the same build and configuration.
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

- Count successful partial client writes in protocol fingerprints, including
  when a later write fails. Retry interrupted writes and reject zero-progress
  writes without losing the accepted prefix from delivery accounting.

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
