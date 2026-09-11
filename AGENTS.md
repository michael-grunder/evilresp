# AGENTS.md

Working agreement for agents and contributors changing `evilresp`. Keep it
short, concrete, and current: if something here no longer matches the code,
fix this file in the same change.

## What This Project Is

`evilresp` is an intentionally hostile RESP proxy for deterministically fuzzing
Redis, Valkey, and DragonflyDB clients (PhpRedis, hiredis, redis-py, ...). It
sits between a client and a real upstream server, proxies commands unchanged by
default, and mutates replies or cluster topology on demand via `DEBUG EVIL`.

- Rust 2024 edition, async on `tokio`, CLI via `clap`, logging via `tracing`.
- `README.md` is the source of truth for user-facing behavior and command
  syntax. Read it before changing anything a user can observe.
- `specs/` holds the original design intent. It is historical; when it
  disagrees with `README.md` or the code, the code wins.
- `CHANGELOG.md` follows Keep a Changelog with an `## Unreleased` section.

## Commands

```bash
cargo build
cargo run -- --proxy localhost:6379            # listens on 127.0.0.1:6380
cargo run -- --proxy localhost:6379 -vv        # verbose human logs
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo test <name_substring>                    # single test or module
```

Tests do not need a running Redis. They spin up in-process fake upstreams
(`UnixStream::pair`, `UnixListener` on unique temp paths, ephemeral TCP).

## Repository Map

All code lives in one crate: `src/lib.rs` exposes the modules, `src/main.rs`
is a thin binary that parses the CLI, initializes logging, and calls
`proxy::run`. Keep `main.rs` that thin.

| Module                    | Owns                                                                                                                          |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `cli.rs`                  | `clap` args, `Endpoint` (`host:port` or `unix:/path`), `LogMode`.                                                             |
| `logging.rs`              | `tracing-subscriber` setup: human/colored vs JSON lines, verbosity mapping.                                                   |
| `error.rs`                | `AppError` (`thiserror`) and `AppResult<T>`. Add variants here, not ad-hoc types.                                             |
| `resp.rs`                 | RESP2/RESP3 `Frame` type, parsing, encoding, raw frame reads off a stream.                                                    |
| `proxy.rs`                | Listener/accept loop, per-connection state, command dispatch, local `DEBUG`/`MONITOR` handling, reset epochs. Largest module. |
| `evil.rs`                 | `EvilConfig` parsing (`DEBUG EVIL ...`), include/exclude filters, canonicalization, and deterministic mutation seeding.         |
| `mutation.rs`             | Original-frame selection, structure-preserving scalar mutation, frame replacement, random generation, and length corruption. |
| `topology_evil.rs`        | Fake/altered `MOVED`/`ASK` redirections, independent of RESP mutation.                                                        |
| `cluster.rs`              | Startup `CLUSTER SLOTS` probe, `Topology`, mapping upstream nodes to local listeners.                                          |
| `cluster_rewrite.rs`      | Rewriting `CLUSTER SLOTS`/`SHARDS`/`NODES` replies and redirections to local listeners.                                        |
| `protocol_fingerprint.rs` | Per-connection BLAKE3/TLSH fingerprints of client-in and client-out bytes.                                                     |
| `repro.rs`                | `--repro-file` JSONL writer and `ReproRecord` schema.                                                                         |
| `transaction.rs`          | Tracking upstream-acknowledged transaction commands for `EXEC` reply canonicalization.                                      |

Add new modules around a responsibility (parsing, model, execution, I/O,
config), not around an incidental category. Prefer a new focused file over
growing `proxy.rs` further.

## Invariants (Do Not Break)

These are the properties the whole tool exists to provide. Changes that touch
them need a test proving they still hold.

- **Mutations are deterministic and connection-independent.** Mutated output is
  a pure function of `(seed, command index, command bytes, canonicalized
  upstream reply bytes)`. The RNG is `ChaCha20Rng` seeded from a SHA-256 digest
  of those inputs (`evil.rs::rng_for`). Never feed connection ids, wall-clock
  time, thread ids, or map iteration order into that path.
- **Same input, same bytes on the wire.** There is regression coverage for
  identical evil sessions producing identical protocol output; keep it green.
- **Local commands never reach the upstream.** `DEBUG EVIL`, `DEBUG PROTOCOL`,
  and `MONITOR` are answered by evilresp itself.
- **Clients can always bootstrap.** `CLUSTER SLOTS`, `CLUSTER SHARDS`, and
  `CLUSTER NODES` bypass reply mutation and do not consume a command index
  in cluster mode. The default exclude list in
  `evil.rs::DEFAULT_EXCLUDED_COMMANDS` exists for the same reason; extend it
  deliberately, not casually.
- **Evil config is per client connection.** New connections start non-evil.
  Shared state is limited to what must be global (command index, reset epoch,
  monitor fan-out, repro writer).
- **`DEBUG EVIL MODE RESET` bumps the reset epoch.** Connections from an older
  epoch are closed before they can consume a command id. Anything that adds
  incrementing global state must participate in this reset.
- **Cluster redirections always point back at evilresp.** Upstream `MOVED`/
  `ASK` targets and topology replies are rewritten to local listeners; nodes
  with no local listener are removed, not exposed. Discovered primaries and
  replicas each have a listener, with primary ports allocated first.
- **The repro JSONL record is a contract.** External tooling parses it. Add
  fields; do not rename or remove existing ones without a changelog entry.

## Code Conventions

- `rustfmt.toml` sets `max_width = 80` and grouped imports
  (`std` / external / crate). Run `cargo fmt`; do not hand-format.
- Clippy runs with `-D warnings`. Fix lints rather than `#[allow]`-ing them;
  if an allow is truly needed, put a one-line reason next to it.
- Return `AppResult` from fallible code. Reserve `panic!`, `unwrap`, and
  `expect` for local, obvious invariants (comment why) and for tests.
- Treat partial writes, short reads, parse failures, and interrupted I/O as
  normal failure modes: a hostile-by-design proxy must not itself fall over on
  them.
- Validate external input (CLI args, `DEBUG` argv, upstream replies) at the
  edge and pass typed values inward. Small domain types beat raw
  `String`/`u64`/tuples crossing module boundaries.
- Keep side effects (sockets, files, clocks) at the edges so core logic in
  `evil.rs`, `resp.rs`, `cluster_rewrite.rs`, and `topology_evil.rs` stays
  unit-testable without I/O.
- Expose only what other modules need. Do not make internals `pub` for test
  convenience; tests live inline and can see private items.
- Dependencies are intentional. Before adding a crate, check that nothing
  already in `Cargo.toml` covers it and that it is maintained.

## Testing

- Tests are inline `#[cfg(test)] mod tests` blocks in each module; there is no
  `tests/` directory. Async tests use `#[tokio::test]`.
- Every behavior change ships with a test covering the success path and at
  least one meaningful failure path. Bug fixes add a regression test that fails
  without the fix.
- Mutation and canonicalization tests should assert on exact bytes or exact
  frames with a fixed seed. If a test needs a specific RNG outcome, pick a seed
  that produces it and say so in the test.
- No tests may depend on wall-clock timing, a real Redis, network reachability,
  fixed port numbers, or test ordering.

## Documentation And Changelog

- Update `README.md` whenever a change affects how users run, configure, or
  interpret evilresp (new `DEBUG` subcommand, flag, mode, default, or
  limitation). Document actual behavior, not intended behavior.
- Add a `CHANGELOG.md` entry under `## Unreleased` for every user-visible or
  contract-relevant change, using `### Added` / `### Changed` / `### Fixed` /
  `### Removed` / `### Deprecated` / `### Security` as applicable.
- Module-level `//!` docs are welcome where a module has a non-obvious job
  (see `cluster_rewrite.rs`). Keep them short and true.

## Workflow

- Read the relevant code before editing it. Check `git status` first and leave
  unrelated in-progress changes alone.
- Keep changes scoped to the task. Do not reformat unrelated files, rewrite
  `Cargo.lock` without cause, or "tidy up" as a side effect.
- Do not commit, push, or tag unless explicitly asked.
- When in doubt about a behavior question, prefer reading `README.md` and the
  tests over guessing from the spec.

## Definition Of Done

A change is complete only when all of the following are true:

1. `cargo fmt` produces no diff.
2. `cargo clippy --all-targets --all-features -- -D warnings` is clean.
3. `cargo test --all-targets --all-features` passes.
4. New or changed behavior has tests, and the invariants above still hold.
5. `CHANGELOG.md` has an entry under `## Unreleased`.
6. `README.md` is updated if user-facing behavior changed.
7. The summary states what changed and names any check that could not be run.
