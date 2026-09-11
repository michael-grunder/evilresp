# evilresp

`evilresp` is an intentionally hostile RESP proxy for deterministically fuzzing
Redis, Valkey, and DragonflyDB clients.

By default it behaves like a normal RESP server: commands are proxied to a real
upstream server and replies are returned unchanged. Evil behavior is configured
at runtime with `DEBUG EVIL` commands.

## Running

Run `evilresp --help` for available options and usage examples.

Build with a current stable Rust toolchain on a Unix platform:

```bash
cargo build --release
./target/release/evilresp --proxy localhost:6379
```

Or build and run the debug binary directly:

```bash
cargo run -- --proxy localhost:6379
```

The server listens on `127.0.0.1:6380` by default. Use `--listen` to choose a
different local address:

```bash
cargo run -- --proxy localhost:6379 --listen 127.0.0.1:6381
```

For a TCP listener with a TCP upstream, `--listen` requires a numeric IP
address; use brackets for IPv6, for example `[::1]:6380`. The upstream may
use a hostname.

Use `unix:/path/to/socket` to proxy an upstream AF_UNIX socket, listen on an
AF_UNIX socket, or both:

```bash
cargo run -- --proxy unix:/tmp/redis.sock --listen unix:/tmp/evilresp.sock
```

At startup, `evilresp` probes `CLUSTER SLOTS`. If the upstream is a cluster, it
maps each primary node to a local listening port and rewrites `CLUSTER SLOTS`,
`CLUSTER SHARDS`, and `CLUSTER NODES` responses and upstream `MOVED`/`ASK`
redirections so cluster-aware clients connect back through `evilresp`,
whichever discovery command they use. `CLUSTER SLOTS` is synthesized from the
startup probe; `CLUSTER SHARDS` and `CLUSTER NODES` are answered by the
upstream and rewritten, with nodes that have no local listener (replicas)
removed rather than exposed, and announced hostnames replaced or blanked. The
three topology queries bypass reply mutation and do not consume a command
index, so a client can always bootstrap. Cluster proxy mode requires TCP
endpoints; configuring either endpoint as AF_UNIX uses standalone proxy mode.

Cluster listeners use consecutive ports starting at `--listen`, which must
be nonzero in cluster mode. Discovery runs once at startup. If it fails
(including an authentication error), the proxy falls back to standalone mode.
In cluster mode, a redirection to a target with no mapped local listener
returns `ERR evilresp has no local listener for redirection target`. Restart
the proxy to discover changed topology. Rewriting also happens before RESP
mutation, including when its probability is zero.

## MONITOR

`MONITOR` is handled by `evilresp` and is not sent upstream. It returns `OK`
and then streams Redis-style monitor lines for commands received from other
connected clients:

```bash
redis-cli -p 6380 MONITOR
```

Monitor lines include the evilresp connection id as a Redis-compatible
`unix:evilresp:<id>` client address and quoted command arguments.

## Logging

Human-readable colored logs are the default. Increase verbosity with `-v` or
`-vv`. Logs go to stderr. `RUST_LOG`, when valid, overrides the verbosity
filter.

Warnings for rejected `DEBUG PROTOCOL` commands identify the invalid argument
and its valid choices, or report a missing argument or the first extra argument.
With `-v` or `-vv`, an additional debug log includes the complete parsed
argument array as `argv=["DEBUG", "PROTOCOL", ...]`, with quoted strings and
escaped control characters.

```bash
cargo run -- --proxy localhost:6379 -v
```

Use JSON lines for machine-readable logs:

```bash
cargo run -- --proxy localhost:6379 --log-mode json
```

## Repro JSONL

Use `--repro-file <path>` to append one JSON object per mutated reply:

```bash
cargo run -- --proxy localhost:6379 --repro-file repro.jsonl
```

Each record includes the global seed, connection id for observability,
deterministic command index, command bytes/hash, upstream response bytes/hash
when applicable, mutated response bytes/hash, selected evil mode, and applied
mutation list. Mutated RESP output is determined by the seed, command index,
command bytes, and canonicalized upstream response bytes when applicable, not
by the client connection id.

Byte fields use hex encoding, and the record's hashes use SHA-256. The field
`global_seed` is retained for compatibility; it contains the seed configured
on the connection that produced the record. Upstream bytes and their hash are
the original response, before cluster rewriting or canonicalization, and are
`null` in `RANDOM` mode. Mutation entries contain `path` and `kind` fields.
Write failures are logged and do not stop proxying.

For a reproducible run, use the same configuration, command order, and
upstream data. Command indexes are shared across connections, start at zero,
and count ordinary commands even in `OFF` mode or when excluded by a filter.
Local commands and cluster-mode topology queries do not consume indexes.
Concurrent clients can interleave differently between runs; serialize their
commands when reproducing a failure. RESP mutation uses ChaCha20 seeded from
SHA-256 of the seed, command index, command hash, and canonicalized reply hash.

## DEBUG EVIL

`DEBUG EVIL` commands are handled by `evilresp` and are not sent upstream.
Evil configuration is scoped to the current client connection. New client
connections always start with the default non-evil configuration and must send
their own `DEBUG EVIL` setup commands.

```text
DEBUG EVIL SEED <seed>
DEBUG EVIL MODE <OFF|RANDOM|MUTATE|OVERFLOW> [PROBABILITY <0.00-100.00>]
DEBUG EVIL TOPOLOGY <0.00-100.00>
DEBUG EVIL MODE RESET
DEBUG EVIL CANONICALIZE <ALL|UNORDERED|NONE>
DEBUG EVIL STATUS
DEBUG EVIL INCLUDE <arg1> ... <argN>
DEBUG EVIL EXCLUDE <arg1> ... <argN>
```

The default seed is `0`. Seeds must be unsigned 64-bit integers, and
probabilities must be finite numbers between `0` and `100`. Invalid commands
return an error without changing the current configuration. `SEED` and
`STATUS` reject extra arguments.

Modes:

- `OFF`: proxy without modifying replies.
- `RANDOM`: return deterministic random RESP frames without consulting the
  upstream for included commands.
- `MUTATE`: proxy the command, parse the upstream reply, and recursively mutate
  typed RESP frames.
- `OVERFLOW`: mutate toward overflow-prone values and lengths.

Selecting a mode resets its probability to `100` (`0` for `OFF`) unless an
explicit probability is supplied. In `MUTATE` and `OVERFLOW`, probability
applies to each visited frame and a separate length-corruption attempt, not
to the reply as a whole. `RANDOM` always generates a reply for eligible
commands; its `PROBABILITY` setting currently has no effect.

Configure and exercise the proxy on the same connection, for example in an
interactive `redis-cli -p 6380` session:

```text
DEBUG EVIL MODE RESET
DEBUG EVIL SEED 1234
DEBUG EVIL INCLUDE GET
DEBUG EVIL MODE MUTATE PROBABILITY 10
GET example
DEBUG EVIL STATUS
```

Mutated replies can intentionally violate RESP framing, so the client may
disconnect before subsequent commands can run.

`DEBUG EVIL TOPOLOGY` controls cluster redirection lies independently from RESP
reply mutation. In cluster mode, topology mutation can inject fake `MOVED` or
`ASK` redirections for commands that otherwise succeeded, alter real upstream
redirections, flip redirection kind, choose the wrong slot or server, and emit
wild slot numbers outside Redis' normal `0..16383` range. These replies are
valid RESP errors first, then `MUTATE` or `OVERFLOW` can still corrupt their
RESP shape when those modes are enabled.

`DEBUG EVIL MODE RESET` disables RESP evil mode, sets RESP mutation probability
to zero, resets the deterministic command index, invalidates older client
connections, and resets the current connection's protocol fingerprints.
It preserves the seed, filters, canonicalization setting, and topology
probability. To disable topology mutation too, send `DEBUG EVIL TOPOLOGY 0`.
The reset command and its reply are omitted from the new fingerprints.

Canonicalization controls whether upstream replies are normalized before they
seed and enter the mutation pipeline. The default is `UNORDERED`, which
canonicalizes replies whose order Redis may vary between runs, such as
`HGETALL`, `HKEYS`, `HVALS`, `SMEMBERS`, `SINTER`, `SUNION`, and `SDIFF`,
plus RESP3 map and set containers. `ALL` recursively sorts all RESP
containers. `EXEC` replies are canonicalized element-by-element using the
commands queued since `MULTI`, so unordered replies inside transactions seed
mutation the same way as standalone replies. `NONE` preserves the raw upstream
reply shape.

Transaction bookkeeping follows upstream acknowledgements: rejected commands
do not shift the command names used to canonicalize `EXEC` results. In
`MUTATE` and `OVERFLOW`, canonicalization still runs at probability zero and
may reorder the response. Use `OFF` with topology probability zero for normal
proxy behavior.

Filters are case-insensitive. Plain strings match literal command names, regex
strings such as `^GET.*` match command names, and attributes such as `@read`,
`@write`, `@set`, and `@zset` match the built-in command attribute table.

`INCLUDE` and `EXCLUDE` replace their respective lists. With no arguments,
they clear the list: an empty include list permits all commands, and an empty
exclude list removes the default exclusions. Exclusions take precedence over
inclusions. Attributes come from a small built-in table, not upstream command
introspection; an unknown attribute matches nothing.

The default exclude list avoids mutating commands that commonly break client
setup too early: `AUTH`, `HELLO`, `CLIENT`, `SELECT`, `ASKING`, `MULTI`,
`COMMAND`, `DISCARD`, `SUBSCRIBE`, `PSUBSCRIBE`, `SSUBSCRIBE`, `UNSUBSCRIBE`,
and `QUIT`.

## DEBUG PROTOCOL

`DEBUG PROTOCOL` commands are handled by `evilresp` and are not sent upstream.
They return per-connection fingerprints for RESP bytes received from the client
or written back to the client:

```text
DEBUG PROTOCOL <IN|OUT> <BLAKE3|TLSH>
```

`BLAKE3` returns a hex digest for exact uniqueness checks. `TLSH` returns a TLSH
similarity hash, or `TNULL` until the observed byte stream is large and varied
enough for TLSH. `DEBUG PROTOCOL` requests and replies do not update the
fingerprints they read.

## Protocol limits

Incoming client commands and upstream frames are limited to 64 MiB per frame
(including headers and aggregate contents) and 128 levels of nesting,
counting the root frame. Invalid lengths, missing CRLF terminators, truncated
frames, or exceeded limits close the affected connection. These limits do
not restrict intentionally malformed output generated by evil modes.

The proxy processes one command and one upstream frame at a time. It supports
ordinary request/reply traffic and buffered pipelines, but does not handle
unsolicited Pub/Sub messages, RESP3 push delivery, or attribute frames attached
to replies as a complete asynchronous conversation. Streamed RESP3 strings
and aggregates are unsupported. Inline commands are split on whitespace;
use RESP arrays for quoting, spaces within arguments, or binary arguments.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

Tests use in-process fake upstreams and require no running Redis server.
See [AGENTS.md](AGENTS.md) for the module map and contributor conventions.
