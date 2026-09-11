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

At the default INFO level, one `proxy statistics` summary is logged about
every second, combining all listeners (including cluster nodes). Fields are:

- `clients_total`: client connections accepted since startup, including those
  whose upstream connection fails; `clients_active`: connections still handled
  by the proxy, including monitor clients.
- `evil_updates`: successful `DEBUG EVIL` configuration commands, including
  repeated settings and `MODE RESET`, excluding `STATUS` and `HELP` reads.
- `evil_status_reads`, `evil_rejected`, and `evil_resets`: successful status
  reads, rejected `DEBUG EVIL` commands, and successful reset commands.
- `mode_off`, `mode_random`, `mode_mutate`, and `mode_overflow`: successful
  explicit selections of each mode. Resets are counted separately, and new
  clients starting in `OFF` do not count as mode selections. These count
  configuration commands, not mutated replies or clients currently in a mode.

All totals accumulate for the process lifetime and survive `MODE RESET`;
`clients_active` is a current count. Concurrent updates can make fields reflect
slightly different instants. Delayed summaries skip missed intervals instead
of emitting a burst of catch-up logs.

Individual configuration changes, including the full status, are logged at
DEBUG (`-v` or `-vv`). `STATUS` and `HELP` reads do not log configuration changes.
Rejected commands still produce warnings.

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

Use `--repro-file <path>` to append one JSON object per mutated reply,
applied transport fault, or ordinary reply delivery failure:

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
`null` in `RANDOM` mode or when a topology redirect or connection fault
bypasses forwarding the command. Mutation entries contain `path` and `kind`
fields.
Length faults keep `kind: "wrong_length"` and add a `length` object containing
the applied corruption `kind`, `original` length, and `replacement` length.
Both lengths are decimal strings, including values beyond integer ranges.
Other mutations omit `length`. Paths identify the actual encoded target,
for example `root.1.0.value` for the value of the first map pair inside the
second array child. Paths refer to the canonicalized tree; in `MANY`, they
also reflect preceding value mutation.
Repro-file write failures are logged and do not stop proxying.

Records retain `mutated_response_bytes_hex` and its hash as the full response
**before transport faults**. For a connection fault at `BEFORE`, no reply
was obtained or generated: these response fields contain empty bytes and
their hash. Delivery adds these fields:

- `delivery_plan`: version `1`, `extra_reply_count`, `extra_reply_bytes_hex`,
  `truncate_at` (a byte offset or `null`), and `chunk_ends` (exclusive byte
  offsets into the planned stream, including its final end). A non-null
  truncation offset requires write-side shutdown after the last chunk.
- `planned_wire_bytes_hex`: response plus extra replies, cut at the selected
  offset. This is the complete intended byte stream, even if delivery failed.
- `delivery_outcome`: `bytes_written`, SHA-256 `written_bytes_hash`,
  `completed_chunks`, `shutdown_completed`, `error_stage` (`write`, `flush`,
  `shutdown`, `reset`, `stall`, or `null`), and `error_kind` (Rust I/O error
  kind or `null`).
  The written bytes are exactly the first `bytes_written` bytes of the planned
  stream. A completed chunk includes a successful flush.

Plans that select a connection fault use version `2` and retain all version
`1` fields. They add `connection_fault` with `action` (`close`, `reset`, or
`stall`), `point` (`before`, `after`, `reply`, `random`, or `{"bytes": n}`),
resolved `after_bytes`, and `duration_ms` (only non-null for an explicit
stall). `truncate_at` is null for these plans; `after_bytes` limits their
wire stream. Without a selected connection fault, plans remain version `1`.

For version `2`, delivery outcomes add `fault_completed`, indicating whether
local termination succeeded, and optionally `stall_end` (`duration_elapsed`
or `peer_closed`). A read failure during stalling uses `error_stage: "stall"`.
Reset preparation failures use `error_stage: "reset"`. A reset uses abortive
socket close without write-side shutdown, so `shutdown_completed` remains
false even when `fault_completed` is true. Accepted bytes may be discarded
by the kernel during reset; neither field proves the peer received them.

To replay version `1` delivery without regenerating mutations, decode the
planned bytes, write and flush each slice ending at `chunk_ends`, then shut down the write
side if `truncate_at` is non-null. The plan can also reconstruct those bytes:
append the recorded extra reply the recorded number of times to the original
mutated response, then truncate. Empty output has no chunks. Transport-only
records may have an empty `mutations` list and mode `OFF`. For version `2`,
write the planned chunks, then perform `connection_fault.action`: orderly
shutdown and close, TCP abortive close, or withhold further output for
`duration_ms` before closing (ending early on peer EOF/error). Do not use an
orderly shutdown before a reset. To reconstruct version `2` wire bytes from
the original response and extras, cut them at `after_bytes`.

Records are appended after the delivery attempt, before processing another
command or returning an I/O error. This captures observed partial-write and
shutdown failures. Connection-fault records are appended after the socket
is closed, including when a stall ends on peer EOF/error. A pending stall or
blocked/cancelled delivery has no completed record yet. The deterministic
plan describes intended delivery; OS errors and how much a peer receives are
observations, not seeded fault choices.

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
DEBUG EVIL HELP
DEBUG EVIL SEED <seed>
DEBUG EVIL MODE <OFF|RANDOM|MUTATE|OVERFLOW> [PROBABILITY <0.00-100.00>]
DEBUG EVIL STRATEGY <PRESERVE|REPLACE>
DEBUG EVIL MUTATIONS <ONE|MANY>
DEBUG EVIL GENERATOR [PROTOCOL <RESP2|RESP3>] [CORPUS <BOUNDARY|RANDOM>] [VIOLATIONS <OFF|ON>]
DEBUG EVIL FRAMING <AUTO|OFF>
DEBUG EVIL FRAMING LENGTH [PROBABILITY <0.00-100.00>] [TARGET <ANY|path>] [KIND <RANDOM|SHORTER|LONGER|NEGATIVE|BOUNDARY|OVERFLOW>]
DEBUG EVIL TRANSPORT OFF
DEBUG EVIL TRANSPORT [TRUNCATE <OFF|RANDOM|bytes>] [EXTRA <0..16>] [CHUNKS <OFF|RANDOM|offsets>] [PROBABILITY <0.00-100.00>] [FAULT <OFF|CLOSE|RESET|STALL>] [AT <BEFORE|AFTER|REPLY|RANDOM|bytes>] [DURATION <1..3600000>]
DEBUG EVIL TOPOLOGY <0.00-100.00>
DEBUG EVIL TOPOLOGY OFF
DEBUG EVIL TOPOLOGY REDIRECT [PROBABILITY <0.00-100.00>] [KIND <MOVED|ASK|RANDOM>] [TARGET <WRONG_NODE|SELF|REPLICA|NEXT|RANDOM|host:port>] [SLOT <CORRECT|WRONG|WILD|0..16383>] [PHASE <BEFORE|AFTER>] [KEY <argument-index>] [UNTIL <command-index|OFF>]
DEBUG EVIL MODE RESET
DEBUG EVIL CANONICALIZE <ALL|UNORDERED|NONE>
DEBUG EVIL STATUS
DEBUG EVIL INCLUDE <arg1> ... <argN>
DEBUG EVIL EXCLUDE <arg1> ... <argN>
```

`DEBUG EVIL HELP` returns a Redis-style array of subcommand syntax and
indented descriptions, suitable for viewing in `redis-cli`. It accepts no
extra arguments, leaves configuration unchanged, and consumes no command index.

The default seed is `0`. Seeds must be unsigned 64-bit integers, and
probabilities must be finite numbers between `0` and `100`. Invalid commands
return an error without changing the current configuration. `SEED` and
`STATUS` reject extra arguments.

Modes:

- `OFF`: disable RESP mutation. Independent topology and transport faults
  can still apply if configured.
- `RANDOM`: return deterministic random RESP frames without consulting the
  upstream for included commands.
- `MUTATE`: proxy the command, parse the upstream reply, and recursively mutate
  typed RESP frames.
- `OVERFLOW`: mutate toward overflow-prone values and lengths.

Selecting a mode resets its probability to `100` (`0` for `OFF`) unless an
explicit probability is supplied. This controls value mutation; explicit
framing probability is independent. Mode changes preserve the strategy,
mutation count, framing, generator, and transport settings. `RANDOM` always
generates a reply for eligible commands; its `PROBABILITY` setting currently
has no effect.

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

`TRANSPORT` controls reply delivery and established-connection faults,
including in `OFF` and `RANDOM`. It defaults to disabled, uses the same
include/exclude filters, and never touches local commands or cluster bootstrap
queries. It does not consume an extra command index or a `MUTATIONS ONE` slot.
Reply delivery follows topology rewriting and RESP mutation; a selected
connection fault at `BEFORE` bypasses forwarding and reply generation.

- `EXTRA n`: append up to 16 copies of the valid RESP2/RESP3 simple reply
  `+EVILRESP\r\n`. Extras have no corresponding upstream command. The
  connection remains open, allowing tests of reply/command misalignment.
- `TRUNCATE bytes`: send only that many bytes of the response-plus-extras,
  then shut down the write side and end the connection. `0` sends immediate
  EOF. An offset at or beyond the complete stream length is ineligible and
  does not close the connection. `RANDOM` selects a seeded offset from zero
  through length minus one; `OFF` disables truncation.
- `CHUNKS offsets`: split the remaining stream at comma-separated absolute
  byte offsets, for example `1,3,4,8`. Offsets must be strictly increasing
  positive integers, with at most 64 boundaries. Offsets at or beyond the
  remaining length are ignored. `RANDOM` chooses one to 64 seeded boundary
  candidates where possible and coalesces duplicates; `OFF` writes one chunk.
- `PROBABILITY`: percentage chance per eligible command; default `100`.
  Legacy delivery options (`EXTRA`, `TRUNCATE`, `CHUNKS`) share one draw.
  Connection faults use a separate independent draw at the same probability.
  At zero, all transport faults are disabled regardless of RESP probability.
- `FAULT CLOSE`: request orderly write-side shutdown and close the connection.
- `FAULT RESET`: perform TCP abortive close (zero linger) without an orderly
  shutdown, exercising reset-by-peer handling. Rejected on Unix client sockets.
- `FAULT STALL`: explicitly opt in to withholding the remaining reply until
  `DURATION` expires, then close. It ends early on client write-side EOF or a
  read error. Incoming buffered/pipelined data is drained with bounded memory
  and counted in input fingerprints, but never executed or assigned indexes.
- `FAULT OFF`: disable connection faults while retaining other transport
  settings. All connections start with `FAULT OFF`.
- `AT`: select when the connection fault happens (default `AFTER`), using
  the table below. `AT RANDOM` randomizes only the byte offset, never the
  action; it cannot introduce a stall.
- `DURATION`: stall duration in milliseconds, from `1` to `3600000`, default
  `10000`. It has no effect unless `FAULT STALL` is explicitly selected.

| `AT` | Behavior |
| --- | --- |
| `BEFORE` | Do not forward the selected command or generate its response; send no reply bytes. |
| `AFTER` | Obtain/generate the reply, then apply the fault without sending any reply bytes. |
| `REPLY` | Write the complete response plus selected extras, then apply the fault. |
| `RANDOM` | Write a seeded prefix from zero through total length minus one, then apply the fault (zero for an empty response). |
| `bytes` | Write that many bytes of the response plus selected extras, then apply the fault. An offset equal to the total length is valid; a larger offset skips the connection fault. |

With ordinary proxying, `AFTER` means the command has already executed
upstream, so a retry may repeat a write. `RANDOM` mode and before-forwarding
topology redirects can instead generate a reply without executing upstream.
All connection faults terminate processing of this connection: buffered
commands must not consume further indexes, including during an opted-in stall.
`FAULT` and `TRUNCATE` cannot both be enabled; use `AT bytes` for a connection
fault at a particular offset. `EXTRA` and `CHUNKS` can combine with connection
faults; they have no effect when a selected `BEFORE` fault skips the reply.

**Stalling is never selected implicitly.** `CLOSE` and `RESET` introduce no
artificial delay, regardless of `AT` or `DURATION`. Only `FAULT STALL`
adds a wait, and it never sends the suppressed remainder after that wait.

Options may appear in any order and are case-insensitive. Supply at least
one option/value pair; omitted options retain their values, and invalid or
duplicate options leave all settings unchanged. `TRANSPORT OFF` clears all
transport options and restores transport probability to `100`. Settings are
per connection, appear in `STATUS`, and survive mode changes and reset.

Planning uses a separate, versioned ChaCha20 RNG derived from the seed,
command index, command hash, and canonicalized response hash used by RESP
mutation (empty in `RANDOM`). With RESP mutation off, canonicalization is
used only for the transport seed; relayed bytes retain their order. Transport
settings do not change the RESP RNG stream or chosen value/framing mutations.
Connection-fault selection and random offsets use their own domain-separated
RNG from seed, command index, and command hash, without needing an upstream
reply. Clock readings and actual socket outcomes never affect those choices.

Each planned chunk is fully written and flushed before the next starts.
Short writes finish the current chunk; interrupted writes are retried.
Chunk boundaries specify proxy writes, not TCP packets or client reads:
socket buffering may split or combine them. Only an explicit `FAULT STALL`
uses a wall-clock delay.
Truncation calls write-side shutdown and ends command processing, so queued
client commands are not forwarded or assigned indexes. Any write, flush, or
shutdown failure also ends that connection without retrying the whole reply.

For example, test EOF inside a bulk payload while keeping its RESP header:

```text
DEBUG EVIL MODE OFF
DEBUG EVIL INCLUDE GET
DEBUG EVIL TRANSPORT TRUNCATE 6 CHUNKS 1,3,4
GET example
```

An upstream `$3\r\nfoo\r\n` becomes `$3\r\nfo` followed by EOF. Reconnect
and configure `TRANSPORT EXTRA 1 CHUNKS RANDOM` to test surplus replies with
seeded fragmentation instead.

For a 10% chance of reset before executing the command, on a TCP connection:

```text
DEBUG EVIL TRANSPORT OFF
DEBUG EVIL TRANSPORT FAULT RESET AT BEFORE PROBABILITY 10
```

Use `AT AFTER` to test ambiguous execution, `AT 6` to reset after a reply
prefix, or `FAULT CLOSE AT REPLY` to test replacement of closed pooled
connections after successful replies. To specifically test timeouts, opt in:

```text
DEBUG EVIL TRANSPORT OFF
DEBUG EVIL TRANSPORT FAULT STALL AT AFTER DURATION 30000 PROBABILITY 10
```

The `DEBUG` configuration reply itself is unaffected. These controls operate
on already accepted connections and do not simulate TCP handshake refusal or
exhaust OS file descriptors. A reset can discard bytes accepted by the OS;
`AT REPLY` describes proxy writes, not guaranteed client receipt. Normal close
requests orderly shutdown, but the final peer-visible error can still depend
on socket state, unread data, and the OS.

Mutated replies can intentionally violate RESP framing, so the client may
disconnect before subsequent commands can run.

`DEBUG EVIL TOPOLOGY` controls cluster redirection faults independently from
RESP mutation and transport faults. It only operates in cluster mode, honors
`INCLUDE`/`EXCLUDE`, and never changes bootstrap `CLUSTER SLOTS`, `SHARDS`, or
`NODES` replies. Configuration is per connection; configure each connection
that should inject faults, including connections to redirect destinations.
New connections start with topology faults disabled.

`DEBUG EVIL TOPOLOGY <probability>` retains the original mixed algorithm and
seeded output. It can replace ordinary replies with fake `MOVED`/`ASK`, flip
redirection kind, change destinations among mapped primaries, and change slots
to valid or arbitrary signed values. The probability is checked separately
for several mutations, so multiple changes can affect one reply. Except in
`RANDOM` mode, this happens after the upstream has processed the command.

`DEBUG EVIL TOPOLOGY REDIRECT` selects a focused fault. Each command starts
from the defaults below; omitted settings do not retain a previous redirect
configuration. Options are case-insensitive, may appear in any order, and
must not repeat. Invalid updates leave all topology settings unchanged.

| Option | Default | Behavior |
| --- | --- | --- |
| `PROBABILITY` | `100` | One probability check per eligible command at the selected phase. |
| `KIND` | `MOVED` | Emit `MOVED`, `ASK`, or a seeded random choice of the two. |
| `TARGET` | `WRONG_NODE` | Choose the destination as described below. |
| `SLOT` | `CORRECT` | Use the key's slot, a different valid slot (`WRONG`), an out-of-range signed 32-bit slot (`WILD`), or a fixed slot `0..16383`. |
| `PHASE` | `BEFORE` | Inject before forwarding, or replace the upstream reply with `AFTER`. |
| `KEY` | `1` | Argument index containing the key, with command name at index `0`. |
| `UNTIL` | `OFF` | Stop injecting when the shared command index reaches this exclusive cutoff. |

Destinations:

- `WRONG_NODE`: a mapped primary other than the slot's owner in the startup
  topology. This can be the current listener if the request is already at
  the wrong node.
- `SELF`: the current mapped listener, for redirects that make no progress.
- `REPLICA`: a mapped replica of the slot's owner.
- `NEXT`: the next distinct primary in startup topology order, wrapping back
  to the first. A replica listener redirects to the first primary. Requires
  at least two primaries; with two primary listeners it produces A/B bouncing.
- `RANDOM`: a seeded choice among distinct mapped primaries, including the
  correct owner or the current listener.
- A literal `host:port` (IPv6 as `[address]:port`): advertise that exact
  destination, even if it is not in the cluster. This is the explicit exception
  to keeping redirects inside evilresp. The proxy does not resolve or probe
  the destination; connection success, refusal, and DNS failures are client
  observations. Use a controlled endpoint to test those outcomes.

An unavailable target, such as a shard without replicas, skips the fault.
`CORRECT`, `WRONG`, and `WILD` require a string key at `KEY`; missing or
non-string arguments skip the fault. Hashing uses the original binary key and
Redis hash tags. This is positional key selection, not Redis command-key
introspection: use `KEY 3` for a single-key `EVAL`, for example. `SLOT <number>`
works without a key and uses that slot for owner/replica lookup. For `WRONG`
and `WILD`, destinations are selected using the original key's slot before
changing the advertised slot.

`BEFORE` prevents the selected command from executing upstream. `AFTER`
replaces any ordinary or redirection reply after execution, so retrying a
write can execute it again. `RANDOM` mode never forwards eligible commands:
only `BEFORE` redirects apply there, with normal random generation when no
redirect applies. In `MUTATE`/`OVERFLOW`, the injected error still passes
through RESP mutation. Transport faults can also alter its delivery. To
isolate routing behavior, use `MODE OFF` and `TRANSPORT OFF`.

`ASK` is the error returned to the client; `ASKING` is the command the client
sends on the destination connection before retrying. `ASKING` remains in the
default exclude list and is proxied normally.

For wrong-node redirects that keep the slot correct:

```text
DEBUG EVIL MODE OFF
DEBUG EVIL TOPOLOGY REDIRECT PROBABILITY 10 KIND MOVED TARGET WRONG_NODE
```

For a bounded bounce experiment, first reset on one connection, then open or
reopen the other connections and configure **each** participating connection:

```text
DEBUG EVIL TOPOLOGY REDIRECT TARGET NEXT UNTIL 3
```

Starting at command index zero with two primaries and only eligible test
commands, indexes `0`, `1`, and `2` redirect; index `3` is forwarded normally.
`UNTIL` is an absolute global command-index boundary, not a per-request retry
count or a count since configuration. Other clients and excluded ordinary
commands (including `ASKING`) also advance it. Local commands and bootstrap
queries do not. Stopping injection permits normal routing/recovery; successful
recovery still depends on the real cluster, the client's retry budget, and
other enabled faults.

The cutoff introduces no separate retry counter. `MODE RESET` resets the
existing command index and thus re-arms a preserved cutoff, while invalidating
older connections. The same seed, command indexes, command bytes, upstream
replies for `AFTER`, and mapped topology/current listener produce the same
redirects. Repro mutations identify the phase as `topology_redirect_before`
or `topology_redirect_after`; before-forwarding records have null upstream
response fields. Actual reply bytes and transport outcomes remain recorded
through the existing repro fields.

`TOPOLOGY OFF` disables both topology forms. A numeric `TOPOLOGY` command
switches back to the legacy algorithm. `STATUS` retains `topology_probability`
and adds `topology=LEGACY|REDIRECT`; focused mode also reports all redirect
options. Topology settings survive RESP mode changes and `MODE RESET`.

`DEBUG EVIL MODE RESET` disables RESP evil mode, sets RESP mutation probability
to zero, resets the deterministic command index, invalidates older client
connections, and resets the current connection's protocol fingerprints.
It preserves the seed, filters, canonicalization setting, mutation strategy,
mutation count setting, framing, generator and transport configuration, and
topology probability.
To disable the independent faults too, send `DEBUG EVIL TOPOLOGY 0` and
`DEBUG EVIL TRANSPORT OFF`.
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
probability zero. Use `OFF` with topology probability zero and transport off
for normal proxy behavior.

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

Output fingerprints count each byte accepted by the client writer, including
extra replies and a prefix accepted before an I/O failure. Omitted bytes after
truncation are not counted. Identical bytes have identical fingerprints
regardless of chunk boundaries or short writes. A successful socket write
does not prove the peer received or parsed those bytes. Fingerprints cannot
be queried on a connection after truncation closes it; repro delivery outcomes
retain the accepted byte count and SHA-256 hash for that reply.

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
