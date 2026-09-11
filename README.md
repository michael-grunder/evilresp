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
maps each primary and replica node to a local listening port and rewrites
`CLUSTER SLOTS`, `CLUSTER SHARDS`, and `CLUSTER NODES` responses and upstream
`MOVED`/`ASK` redirections so cluster-aware clients connect back through `evilresp`,
whichever discovery command they use. `CLUSTER SLOTS` is synthesized from the
startup probe; `CLUSTER SHARDS` and `CLUSTER NODES` are answered by the
upstream and rewritten, with nodes that have no local listener removed rather
than exposed, and announced hostnames replaced or blanked. The
three topology queries bypass reply mutation and do not consume a command
index, so a client can always bootstrap. Cluster proxy mode requires TCP
endpoints; configuring either endpoint as AF_UNIX uses standalone proxy mode.

Cluster listeners use consecutive ports starting at `--listen`, which must
be nonzero in cluster mode. Primaries are assigned ports first, in their order
of first appearance in the startup response, followed by replicas in the same
order. For example, three primaries and three replicas starting at `6380` use
`6380–6382` for primaries and `6383–6385` for replicas. Repeated nodes across
slot ranges share a listener; node IDs and primary/replica relationships are
preserved. Nodes are matched by node ID when available and by full upstream
endpoint, so different hosts using the same port get separate listeners.
Topology rewriting can also match an alternative address by port when that
port identifies only one mapped node. Conflicting node identities or a local
port range exceeding `65535` stop startup with an error.

Each replica listener forwards to that actual upstream replica, including
client `READONLY` and `READWRITE` commands. Replica connections start with
their own default non-evil configuration, just like primary connections.

Discovery runs once at startup. If the probe fails (including an
authentication error), the proxy falls back to standalone mode.
In cluster mode, a redirection to a target with no mapped local listener
returns `ERR evilresp has no local listener for redirection target`. Restart
the proxy to discover changed topology, including changed slot ownership or
primary/replica roles after failover; the synthesized `CLUSTER SLOTS` reply
remains a startup snapshot. Rewriting also happens before RESP
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
Length faults keep `kind: "wrong_length"` and add a `length` object containing
the applied corruption `kind`, `original` length, and `replacement` length.
Both lengths are decimal strings, including values beyond integer ranges.
Other mutations omit `length`. Paths identify the actual encoded target,
for example `root.1.0.value` for the value of the first map pair inside the
second array child. Paths refer to the canonicalized tree; in `MANY`, they
also reflect preceding value mutation.
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
DEBUG EVIL STRATEGY <PRESERVE|REPLACE>
DEBUG EVIL MUTATIONS <ONE|MANY>
DEBUG EVIL GENERATOR [PROTOCOL <RESP2|RESP3>] [CORPUS <BOUNDARY|RANDOM>] [VIOLATIONS <OFF|ON>]
DEBUG EVIL FRAMING <AUTO|OFF>
DEBUG EVIL FRAMING LENGTH [PROBABILITY <0.00-100.00>] [TARGET <ANY|path>] [KIND <RANDOM|SHORTER|LONGER|NEGATIVE|BOUNDARY|OVERFLOW>]
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
explicit probability is supplied. This controls value mutation; explicit
framing probability is independent. Mode changes preserve the strategy,
mutation count, framing, and generator settings. `RANDOM` always generates a
reply for eligible commands; its `PROBABILITY` setting currently has no effect.

`STRATEGY` controls value mutation in `MUTATE` and `OVERFLOW`:

- `PRESERVE` (default): retain aggregate containers and mutate their scalar
  children, including map keys and values. Scalar types are retained; their
  generated numeric and verbatim contents are valid unless generator
  violations are enabled. Nulls and empty containers have no mutable scalar
  value. In `OVERFLOW`, booleans
  and inline frames are also ineligible.
- `REPLACE`: allow any original frame, including an entire aggregate, to be
  selected. `MUTATE` replaces it with a random frame; `OVERFLOW` applies
  overflow values and replaces aggregates, nulls, booleans, and inline frames
  with the maximum signed 64-bit integer. Replacement subtrees are not
  recursively mutated again.

`MUTATIONS` controls selection in those same two modes:

- `MANY` (default): apply value probability independently at each eligible
  original frame, then run the framing stage on the resulting tree. A framing
  fault can still break the wire format with `STRATEGY PRESERVE`.
- `ONE`: with `FRAMING AUTO` or `OFF`, apply value probability once to the
  reply, then uniformly select one eligible original frame and change its
  value or replace it. No extra framing fault runs. With explicit
  `FRAMING LENGTH`, try the framing fault first; if it succeeds, it takes the
  single mutation slot and no values change. If its probability check fails
  or its target is ineligible, try value mutation as above. At value
  probability `100`, exactly one RESP mutation occurs if an eligible value
  exists. With no applied mutation, the canonicalized reply is returned
  unchanged and no RESP mutation is recorded.

`FRAMING` separates length faults from value mutation in `MUTATE` and
`OVERFLOW`:

- `AUTO` (default): keep the existing root-only length attempt in `MANY`,
  using the mode's probability. `MUTATE` adds one to the root length;
  `OVERFLOW` advertises `9223372036854775807`. It does nothing in `ONE`.
- `OFF`: disable all length faults while retaining value mutation.
- `LENGTH`: attempt one length fault per reply using its own probability,
  target, and corruption kind. It works even at value probability zero.
  Each `FRAMING LENGTH` command resets omitted options to probability `100`,
  target `ANY`, and kind `RANDOM`. Options can appear in any order;
  duplicate options are rejected. `AUTO` and `OFF` accept no options.

`TARGET ANY` uniformly selects from eligible length headers. A specific path
selects only that frame: `root`, `root.0` for an array/set/push child, or
`root.0.key` / `root.0.value` for a map/attribute pair. Compose paths for
nested frames, for example `root.1.0.value.2`. Indexes are zero-based;
path words are case-insensitive and leading zeros in indexes are normalized.
An absent path, a scalar without a length header, or a pair index without
`.key` or `.value` is ineligible and produces no framing mutation. Empty
containers and RESP2 null strings/arrays do have eligible length headers.

Length corruption kinds:

| Kind | Advertised length |
| --- | --- |
| `SHORTER` | Current length minus one, including `0` to `-1` and `-1` to `-2`. |
| `LONGER` | Current length plus one. |
| `NEGATIVE` | `-2`, `-3`, or the minimum signed 64-bit integer. |
| `BOUNDARY` | `0`, `1`, signed 32-bit maximum and its successor, unsigned 32-bit maximum and its successor, signed 64-bit maximum, or unsigned 64-bit maximum. |
| `OVERFLOW` | Signed 64-bit maximum plus one, unsigned 64-bit maximum plus one, signed 64-bit minimum minus one, or unsigned 128-bit maximum plus one. |
| `RANDOM` | Select one of the five kinds above. |

Only the chosen header's decimal length changes; bodies, terminators, sibling
frames, and other headers retain their encoding. Map and attribute lengths
count pairs. The actual output allocation uses actual contents, never the
advertised length. A boundary matching the current length is replaced by
another boundary so the fault changes bytes. Framing targets the original
canonicalized tree in `ONE`, and the tree after value mutation in `MANY`,
including generated replacements. A path removed by replacement is skipped.

These controls are per connection, appear in `STATUS`, and reject missing,
invalid, or extra arguments without changing configuration. They do not
affect `OFF`, `RANDOM`, or independent topology mutation. Canonicalization
and topology rewriting still precede RESP mutation, so `ONE` limits the RESP
mutation operation count, not every possible difference from upstream bytes.
The new mutation selection changes seeded `MUTATE` and `OVERFLOW` output
relative to earlier versions; reproduce with the same build and settings.

`GENERATOR` controls whole replies in `RANDOM`, replacement trees in
`MUTATE STRATEGY REPLACE`, and scalar contents in `MUTATE`. Defaults are
`PROTOCOL RESP2`, `CORPUS BOUNDARY`, and `VIOLATIONS OFF`:

- `PROTOCOL RESP2`: generate simple strings, errors, signed integers, bulk
  strings, arrays, and both RESP2 null forms. Every generated descendant uses
  RESP2 types when violations are off.
- `PROTOCOL RESP3`: additionally generate doubles, big numbers, booleans,
  maps, sets, bulk errors, and verbatim strings. Nulls use the RESP3 null
  marker. Ordinary generation excludes push and attribute frames.
- `CORPUS BOUNDARY`: choose from edge cases 70% of the time at each supported
  numeric, text, or size choice, with random values otherwise. Cases include empty and
  singleton aggregates, empty versus null values, integer limits and nearby
  values, big numbers beyond 64 bits, negative zero, floating-point extremes,
  infinity, and NaN. Binary payloads include NUL, non-UTF-8 bytes, and embedded
  RESP markers. Boundary sizes are `0`, `1`, `31`, `32`, `33`, `255`, `256`,
  `257`, `4095`, `4096`, and `4097` bytes.
- `CORPUS RANDOM`: skip the weighted boundary tables and generate random
  values and sizes. Random blob contents are at most 256 bytes before any
  error or verbatim prefix is added.
- `VIOLATIONS ON`: also allow malformed double and big-number text, invalid
  verbatim formats, standalone push/attribute frames, and RESP3 booleans in
  the RESP2 profile. These are opportunities for deliberate failures, not a
  guarantee that every reply is invalid. Push and attribute generation tests
  unexpected or incomplete conversations; it does not implement asynchronous
  push delivery or attributes followed by a normal reply.

At least one generator option/value pair is required. Options are
case-insensitive and may appear in any order. Omitted options retain their
current values; duplicates and invalid updates leave all settings unchanged.
Settings are per connection, survive mode changes and reset, and appear in
`STATUS` as `generator_protocol`, `generator_corpus`, and
`generator_violations`.

Protocol selection does not negotiate `HELLO` or translate upstream replies.
`PRESERVE` retains upstream scalar types, including RESP3 types under a RESP2
generator profile. Valid generated values can still have the wrong type for
the command. In `OVERFLOW`, doubles and big numbers use their boundary
corpora, verbatim strings retain a `txt:` prefix, and integer/text overflow
mutations retain their extreme-value behavior. Violations can make numeric
contents malformed in either mutation mode.

Generated trees have at most three levels (root included), four elements or
pairs per aggregate, and 4097 bytes per blob payload including error/verbatim
prefixes. These limits also apply with violations enabled. They bound each
generated replacement independently; total output and traversal budgets for
large upstream trees remain future work.

Length corruption remains independently controlled by `FRAMING`.
`VIOLATIONS OFF` does not disable the default `FRAMING AUTO` fault in
`MUTATE` or `OVERFLOW`; use `FRAMING OFF` for correctly framed values.
The expanded corpus changes seeded output in all three evil modes. Use the
same build and configuration to reproduce a case.

Configure and exercise the proxy on the same connection, for example in an
interactive `redis-cli -p 6380` session:

```text
DEBUG EVIL MODE RESET
DEBUG EVIL SEED 1234
DEBUG EVIL INCLUDE GET
DEBUG EVIL STRATEGY PRESERVE
DEBUG EVIL MUTATIONS ONE
DEBUG EVIL MODE MUTATE PROBABILITY 10
GET example
DEBUG EVIL STATUS
```

To change only the length of a nested reply while retaining its values, use
the same connection for setup and the command:

```text
DEBUG EVIL MODE MUTATE PROBABILITY 0
DEBUG EVIL MUTATIONS ONE
DEBUG EVIL FRAMING LENGTH TARGET root.0 KIND LONGER PROBABILITY 100
MGET first second
```

For this example, the first `MGET` result's bulk length changes. Use
`TARGET ANY` to explore different headers deterministically, or
`FRAMING OFF` to test value mutations without length faults.

To exercise a RESP3 client's value parser with the boundary corpus, configure
the client for RESP3 and issue these commands on its connection:

```text
DEBUG EVIL GENERATOR PROTOCOL RESP3 CORPUS BOUNDARY VIOLATIONS OFF
DEBUG EVIL FRAMING OFF
DEBUG EVIL MODE RANDOM
GET example
```

Switch to `DEBUG EVIL GENERATOR VIOLATIONS ON` to mix deliberate protocol
and conversation faults into subsequent generated replies. This retains the
selected protocol and corpus.

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
It preserves the seed, filters, canonicalization setting, mutation strategy,
mutation count setting, framing and generator configuration, and topology
probability.
To disable topology mutation too, send `DEBUG EVIL TOPOLOGY 0`.
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
may reorder the response; explicit framing faults can also run at value
probability zero. Use `OFF` with topology probability zero for normal
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
