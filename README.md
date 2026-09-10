# evilresp

`evilresp` is an intentionally hostile RESP proxy for deterministically fuzzing
Redis, Valkey, and DragonflyDB clients.

By default it behaves like a normal RESP server: commands are proxied to a real
upstream server and replies are returned unchanged. Evil behavior is configured
at runtime with `DEBUG EVIL` commands.

## Running

```bash
cargo run -- --proxy localhost:6379
```

The server listens on `127.0.0.1:6380` by default. Use `--listen` to choose a
different local address:

```bash
cargo run -- --proxy localhost:6379 --listen 127.0.0.1:6381
```

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
`-vv`.

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

Modes:

- `OFF`: proxy without modifying replies.
- `RANDOM`: return deterministic random RESP frames without consulting the
  upstream for included commands.
- `MUTATE`: proxy the command, parse the upstream reply, and recursively mutate
  typed RESP frames.
- `OVERFLOW`: mutate toward overflow-prone values and lengths.

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

Canonicalization controls whether upstream replies are normalized before they
seed and enter the mutation pipeline. The default is `UNORDERED`, which
canonicalizes replies whose order Redis may vary between runs, such as
`HGETALL`, `HKEYS`, `HVALS`, `SMEMBERS`, `SINTER`, `SUNION`, and `SDIFF`,
plus RESP3 map and set containers. `ALL` recursively sorts all RESP
containers. `EXEC` replies are canonicalized element-by-element using the
commands queued since `MULTI`, so unordered replies inside transactions seed
mutation the same way as standalone replies. `NONE` preserves the raw upstream
reply shape.

Filters are case-insensitive. Plain strings match literal command names, regex
strings such as `^GET.*` match command names, and attributes such as `@read`,
`@write`, `@set`, and `@zset` match the built-in command attribute table.

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
