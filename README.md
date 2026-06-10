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

At startup, `evilresp` probes `CLUSTER SLOTS`. If the upstream is a cluster, it
maps each primary node to a local listening port and rewrites `CLUSTER SLOTS`
responses so cluster-aware clients connect back through `evilresp`.

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

Each record includes the global seed, connection id, per-connection command
index, command bytes/hash, upstream response bytes/hash when applicable, mutated
response bytes/hash, selected evil mode, and applied mutation list.

## DEBUG EVIL

`DEBUG EVIL` commands are handled by `evilresp` and are not sent upstream.

```text
DEBUG EVIL SEED <seed>
DEBUG EVIL MODE <OFF|RANDOM|MUTATE|OVERFLOW> [PROBABILITY <0.00-100.00>]
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

Filters are case-insensitive. Plain strings match literal command names, regex
strings such as `^GET.*` match command names, and attributes such as `@read`,
`@write`, `@set`, and `@zset` match the built-in command attribute table.

The default exclude list avoids mutating commands that commonly break client
setup too early: `AUTH`, `HELLO`, `CLIENT`, `SELECT`, `ASKING`, `MULTI`,
`COMMAND`, `DISCARD`, `SUBSCRIBE`, `PSUBSCRIBE`, `SSUBSCRIBE`, `UNSUBSCRIBE`,
and `QUIT`.
