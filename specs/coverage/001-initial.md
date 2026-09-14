## evilresp

This project is an "evil" RESP (Redis, Valkey, DragonflyDB protocol) server with
the main goal of providing a server that can be used to deterministically fuzz
test RESP clients such as PhpRedis, hiredis, redis-py, etc.

### Default baseline behavior

As a baseline the project should behave like a normal RESP server by proxying all
commands to a real server specified by the user at startup. This lets the server
respond to the full range of complex RESP commands correctly without needinig to
fake anything internally.

The project should support both standalone and cluster modes of operation and be
straightforward for the user to set up. So for example

```bash
# Will connect to this endpoint, figure out if it's standalone or cluster and
# and be ready to proxy commands to it.
evilresp --proxy localhost:6379
```

When we connect to a server that is in cluster mode, the evil resp server should
map the keyspace, and then spool up however many listening ports needed to mimic
the cluster topology. Then, it should inform the user how to connect in the cli

### Cli output

The server should log rich (e.g. colorized) and easy for humans to parse info to
the cli or wherever the user redirects output. It can use an idiomatic Rust crate
for the logging machinery and should take multiple log levels depending on how
verbose the user wishes to be.

#### JSOn logging

By default the logging should be for human consumption but the user should be able
to specify `--log-mode json` to produce machine parseable JSON lines.

### Reproducable jsonl files

The user should be able to specify `--repro-file <path>` which will append to a
JSONL file the actual RESP and what we mutated it to for each command.

### Evil mode

A new set of `DEBUG` subcommands should be supported by the server to confiigure
how we want it to be evil.

```
# a uint64_t seed for deterministic fuzzing
DEBUG EVIL SEED <seed> # a uint64_t seed for deterministic fuzzing

# the mode and aggressiveness of evilness
DEBUG EVIL MODE <OFF|RANDOM|MUTATE|OVERFLOW> [PROBABILITY <0.00-100.00>]

# Output the evil mode, temperature, and any INCLUDE/EXCLUDE lists
DEBUG EVIL STATUS

Probability is how likely a mutation is triggered as we walk the RESP reply
recursively.

OFF      - Just proxy commands without doing anything to the replies.
RANDOM   - Pure fuzzing. We just reply with randomized RESP messages not based
           on what command was sent or what the real server replied.
MUTATE   - We send whatever command was sent to us to the proxied server, read
           its RESP response and then recusrively mutate the RESP before
           returning it to the client. This is thinigs like changing bulk or
           multibulk lengths or even changing the reply type inside of the nested
           RESP.
OVERFLOW - Also mutates RESP messages but does so specifically to try and cause
           client overflows (int32_t, int64_t, size_t + size_t overflows, etc).

# Exclude commands or command attributes from fuzzing.
DEBUG EVIL EXCLUDE <arg1>...<argN>

# Include only specific commands or command attributes from fuzzing
DEBUG EVIL INCLUDE <arg1>...<argN>

Valid filtering args:

# String: Treated as a literal command name. The user can use regex as well so
# The server will need a mechanism when receiving commmands to either literally
# match or match the regex. Both literal and regex match should be case
# insensitive.
DEBUG EVIL INCLUDE SET GET LPUSH ^GET.*

# @<string> - A command attribute.
DEBUG EVIL INCLUDE @read @set @zset

# Types can be reasonably simple (read, write, and data type)

If both include and exclude filters are set we can work it like this:

- Include withoug exclude acts as an allowlist
- Exclude without include acts as a blocklist
- If both are set, first filter out with the include list and then filter out
  list.

# Basically any GET* command except GETSET would be fuzzed.
DEBUG EVIL INCLUDE ^GET.*
DEBUG EVIL EXCLUDE GETSET
```

### Reproducability

Every mutated reply should be reproducable with the following information:

- global seed
- connection id
- command index
- command bytes/hash
- upstream response bytes/hash
- selected evil mode

`connection_id` here can be thought of as a monotonically increasing u64 that
increases on each client connection, not some unique identifier that changes
on every command. `command_index` is a monotonically increasing u64 that increases

`command_index` is another monotonically incrementing id but is per connection
so the first command a uzer executes is zero, the second one, etc.

### Excluded commands

Some commands shouldn't be mutated as it would make clients break too early in
the process. A good initial list of excluded commands:

```bash
AUTH
HELLO
CLIENT
SELECT
ASKING
MULTI
DISCARD
SUBSCRIBE
PSUBSCRIBE
SSUBSCRIBE
UNSUBSCRIBE
QUIT
```

### Mutation engine

We are going to start with initial set of mutation logic but this is the main
part of the project so should be well designed and operatate on structured
RESP messages.

We should parse the RESP into strongly typed recursive structure and then apply
mutations as we walk it. The mutatons should also be typed themselves such as
Random, WrongLength, WrongType, etc and should be implemented so they are
easy to extend and add to over time.

There are lots of Rust projects (namely redis-rs) that can do the actual parsing into stronly typed structures so the project is free to either use it directly or
wrap it with our own structures to facilitate this mutation logic.

### Resp version

We should support both RESP2 and RESP3 but shouldn't have to do much around that
since we just need to proxy any HELLO command to the server and then contiinue
to mutate on what the server replied. In RESP3 mode this will include the newer
RESP types and without it will not.
