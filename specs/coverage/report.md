The best way to increase Relay coverage is to combine **valid command sequences with narrowly targeted reply mutations**. Increase the share of replies that reach command formatters and cache operations before adding more corruption. Then run separate campaigns for connection recovery and asynchronous invalidations.

The current snapshot leaves **12,164 executable lines, 877 functions, and 22,134 branches uncovered**. Those are opportunities to investigate, not an estimate of what reply mutation can recover. Many require a particular PHP API, runtime option, server version, or process lifecycle.

This report examines Relay and evilresp as checked out on September 14, 2026. It is a source/coverage analysis; no new fuzzing campaign was run and no coverage improvement is claimed.

I verified that `/home/mike/dev/phpfarm/src/php-8.5.0-debug/ext/relay` resolves to `/home/mike/dev/relay-dev/relay`. All 46 files in the saved HTML report match their current source text, and their covered/uncovered line counts match the supplied summary. Inspected revisions: Relay `c134fe47d6f3797c8890e8c203a2e452e97dd856`; evilresp `1173e4ddaa3b08a85f7340165c50078816969f10`. Existing untracked Relay files were left alone.

The baseline is [the original HTML report](/tmp/relay-coverage.html): lines **59.0% (17,503/29,667)**, functions **67.2% (1,797/2,674)**, branches **34.6% (11,709/33,843)**. The report does not identify which runs contributed counters, so absence of coverage is not proof a path has never executed in another campaign.

The largest gaps, and what can reach them, are:

| File | Line coverage | Missing lines | Branch coverage | Main route to more execution |
| --- | ---: | ---: | ---: | --- |
| `commands.c` | 56.4% | 4,333 | 34.2% | Typed command breadth, valid state, nested reply edits, cache hits |
| `relay.c` | 66.4% | 1,374 | 40.8% | Connection options, reconnects, persistent request lifecycle, event callbacks |
| `table.c` | 5.4% | 1,131 | 1.4% | Direct `Relay\Table` workload; ordinary Redis reply mutations do not invoke it |
| `cluster.c` | 70.2% | 650 | 34.8% | Replica routing, redirects/failover, older-server discovery, malformed discovery fixtures |
| `xxhash.h` | 23.0% | 641 | 18.0% | Input sizes and selected hashing implementations; lower priority as a proxy target |
| `keys.c` | 53.9% | 599 | 39.2% | Populate complete collections, read cached variants, cross representation thresholds |
| `heartbeat.c` | 7.9% | 556 | 10.2% | Separate heartbeat/configuration tests; outside ordinary RESP replies |
| `cache.c` | 68.1% | 519 | 51.3% | Cache admission, invalidation, memory pressure, TLS and adaptive caching configuration |
| `session.c` | 2.6% | 406 | 0.0% | PHP session-handler requests, locking and recovery |
| `hyperloglog.c` | 1.6% | 315 | 0.6% | Cached HLL data followed by local count/merge; cached approximate set cardinality |
| `log.c` | 9.0% | 252 | 7.8% | Enable relevant logging/configuration paths |
| `sentinel.c` | 1.6% | 246 | 0.0% | Instantiate `Relay\Sentinel`, then exercise Sentinel replies |
| `cms.c` | 4.2% | 207 | 1.2% | Relay's adaptive caching/count-min-sketch options and workloads |
| `reader.c` | 8.1% | 193 | 1.7% | Invalidation traffic on an idle persistent connection between PHP requests |
| `command_table.c` | 80.5% | 192 | 60.2% | Additional command names and metadata dispatch |
| `adaptivecache.c` | 28.8% | 84 | 2.1% | Explicit adaptive-cache configuration and activity |
| `pack.c` | 85.8% | 57 | 62.7% | Codec-specific payload edits and serializer configuration |
| `reply.c` | 67.7% | 51 | 53.2% | Inspect call-site availability before assuming more RESP types help |

`commands.c` alone accounts for **35.6% of all missing lines**. However, its missing lines mix argument construction, local cache execution, and reply processing. Reply mutation cannot cover the argument-building code for methods the harness never calls.

The headline percentage includes 2,930 fully covered generated arginfo lines. Excluding arginfo, vendored xxhash, and liblzf gives a supplementary view of **55.25% (14,218/25,734)**. Keep the original metric for comparisons, but also track a fixed set of client parsing, formatting, cache, and transport files. Changing filters is not a coverage gain.

**1. First verify the campaign is reaching the intended surface.**

The checked-out [coverage runner](/home/mike/dev/relay-dev/relay/phpredis-client-fuzzer/fuzz-coverage.sh:1) currently has `evilresp_hooks=()`; the example that enables chaos is commented out. Its actual clients are `redis,relay`, despite a comment about a direct cluster. It enables raw and raw-chaos calls, includes `local,stateful,connection,flush`, and installs `hooks/no-msgpack.php`. These are facts about the current script, not proof that it produced every counter in this snapshot.

Before spending time changing mutation logic:

- Confirm the worker endpoint is an evilresp listener and save `DEBUG EVIL STATUS` plus repro records. A port number and a comment do not establish that faults were armed.
- Run a typed-method campaign alongside the raw campaigns. [relayReturnReply](/home/mike/dev/relay-dev/relay/src/commands.c:16934) calls the command-specific formatter only when the query is not marked raw. Raw traffic still exercises useful code, but it bypasses these formatters and much typed argument handling.
- Audit the effective command catalog and outcome counts. Distinguish a command being selected, failing PHP argument validation, reaching the wire, and successfully entering its formatter. The runner does not enable the blocking or admin categories shown in its include list.
- Keep separate cold-cache and warm-cache workloads. Cache hits never reach evilresp. That is useful for cache testing and counterproductive when the goal is measuring reply mutation throughput.
- Use one isolated proxy per reproducible worker, without competing children sharing its global index. The current runner uses 32 jobs and two forks. Whether different jobs share a proxy must be established from deployment; children using one proxy definitely share its index. The fuzzer already documents that `--forks` and asynchronous cache invalidations complicate replay.
- Audit replica connections too. The current [evilresp hook](/home/mike/dev/relay-dev/relay/phpredis-client-fuzzer/hooks/evilresp.php) discovers masters via `_masters()`; evilresp settings are per connection. Configuring a primary does not arm a replica or a connection opened during an internal retry.

**2. Prioritize valid outer shapes with one invalid nested field.**

This is the most useful evilresp feature addition suggested by the coverage.

Several malformed-reply helpers are never called: `relayMalformedReplyV`, `relayMalformedReplyEx`, `relayMalformedReplyWrongTypeEx`, and `relayReplyFailure` near [commands.c:75](/home/mike/dev/relay-dev/relay/src/commands.c:75). That points to opportunities beyond merely provoking hiredis framing errors.

The existing modes leave a gap. `PRESERVE` retains scalar types and aggregate structure, so it cannot make a two-element record have three elements or turn just its score into an array. `REPLACE` can change types and replace aggregates, but cannot select a requested value path. Replacing an outer container often loses the structure needed to reach a deeper check. `FRAMING LENGTH TARGET ...` can select a path, but changes wire framing rather than producing a correctly encoded structural edit. Focused `EXEC` edits already demonstrate the latter approach for one command.

Add an opt-in, generic tree-edit operation: select an original frame path; replace its type, remove/duplicate/swap one child, or insert a dictionary value; then encode all lengths correctly. Treat whole map pairs and individual key/value edits distinctly. Keep existing defaults and seeded output stable when the feature is disabled. Record the selected path, operation, and before/after shape in repro metadata.

Start with these concrete targets:

| Typed API / reply family | Coverage evidence | Valid setup and useful mutations |
| --- | --- | --- |
| `xRead`, `xReadGroup` | `relayXReadFmt` at 12310 and `relayXReadAddStream` at 12262 are never called | Seed a stream, create a consumer group where needed, obtain messages; preserve stream → entries → ID/message structure, then break exactly one field |
| `xClaim`, `xAutoClaim` | `relayXClaimFmt` at 12057 and `relayXAutoClaimFmt` at 12129 are never called | Create pending entries first; vary JUSTID/full-message paths, cursor shape, missing message fields, and deleted-entry forms |
| `zRange` with scores, `zRandMember`, ZPOP/ZMPOP | Flat-score detector at 12417 never called; malformed nested cases at 12374–12485 untouched | Populate a nonempty sorted set; cover flat and nested member/score replies, odd flat-array cardinality, wrong member type, string/double/invalid score |
| Blocking list and sorted-set pops | `relayBlockingPopReply` at 12503 never called | Use bounded blocking settings and prepopulated keys for success; then nil timeout, wrong tuple size, wrong key/member/score type |
| HMGET/HGETALL and SCAN families | Candidate follow-up targets in existing reply validators | Keep valid root/container types; vary result count, duplicate fields, cursor representation, and one nested item type; measure new branches separately |

The stream-formatting region at lines 12027–12359 has **114 missing executable lines out of 160**, but that is a target inventory, not a promised gain. Source: [stream and sorted-set formatters](/home/mike/dev/relay-dev/relay/src/commands.c:12027).

A normal nonempty nested XREAD response requires more than the generator's three levels. In [generator.rs](/home/mike/dev/evilresp/src/generator.rs:10), generation is limited to depth 3, four items/pairs per aggregate, and 4,097 payload bytes. `RANDOM` therefore cannot synthesize that full nested conversation shape. Mutating a real, successful upstream reply keeps its deeper structure available. Null or empty responses have no scalar mutation candidates under `PRESERVE`, making prepopulation especially important.

For cleanup coverage, place the fault in the **second or later** record as well as the first. This reaches paths that must release already-created PHP arrays or unpacked values before returning an error. For XREAD, preserve the preliminary entry-shape validation and corrupt a later field/value payload to reach cleanup after partial conversion.

**3. Build a deliberate warm-cache mutation campaign.**

The missing `keys.c` functions include array construction/duplication, list cloning, full hash/set conversion, and random map selection. `cache.c` also has untouched invalidation and cleanup functions. Simply generating more GET reply types will not enter these paths.

Use sequences such as populate upstream → successful complete read through Relay → repeated related reads → mutate or externally invalidate → read again. Establish admission first: [relayCacheReply](/home/mike/dev/relay-dev/relay/src/commands.c:16909) will not store a reply without a writer lease, a cacheable database, an applicable put function, and any required validation.

Concrete sequences to add:

- Warm HGETALL, then HGET/HMGET/HRANDFIELD and cached complete/partial reads; include duplicate and numeric-looking fields in accepted replies.
- Warm SMEMBERS, then membership, random selection, union/intersection/difference and cardinality operations on those same keys.
- Warm full list ranges, then indexed/subrange reads, length operations, and writes that invalidate or change the cached representation.
- Query a cached key through an incompatible command, with error throwing both enabled and disabled. `relayReportWrongtype` and `relayCreateWrongtypeException` are untouched at [commands.c:16256](/home/mike/dev/relay-dev/relay/src/commands.c:16256).
- Test sizes on both sides of relevant thresholds. For example, [keys.c:2485](/home/mike/dev/relay-dev/relay/src/keys.c:2485) has a 256-element conversion threshold. Use 255/256/257 actual elements, not just a corrupted header claiming those lengths.

For HLL specifically, cache a valid Redis HLL string via GET, then call single-key and multi-key PFCOUNT. [relayPFCountSingle/Multi](/home/mike/dev/relay-dev/relay/src/commands.c:4178) interpret cached string bytes as an HLL and call count/merge. Start with valid sparse and dense payloads; then alter one header/encoding/register field while retaining the rest. Approximate SUNIONCARD over fully cached sets provides another route to `relayHllAdd` at [commands.c:3407](/home/mike/dev/relay-dev/relay/src/commands.c:3407). This needs the appropriate client/server command support. An arbitrary integer PFCOUNT reply does not exercise HLL parsing.

This suggests a second mutation feature: **bounded byte edits inside an existing bulk payload**, preserving codec or HLL prefixes and most original bytes. Current scalar mutation usually replaces the payload wholesale. Retaining a valid inner-format prefix gives deeper parsers a much better starting point.

**4. Exercise EXEC and pipelines as structured sequences.**

Existing evilresp `EXEC REMOVE`, `DUPLICATE`, and `SWAP` can already target reply/result mismatches without invalid framing. Use heterogeneous queued commands, including strings, integers, arrays, nil and errors, so swapping values has an observable effect. Keep MULTI and QUEUED acknowledgements valid while targeting EXEC.

At [commands.c:16526](/home/mike/dev/relay-dev/relay/src/commands.c:16526), folding depends on queued command metadata and raw/typed flags. Untouched cases include embedded PUSH dispatch around line 16600, some transaction failure paths, and nested pipeline/MULTI handling. Test:

- Transactions with one result removed, duplicated, or moved into another command's position.
- Execution-time error elements with `THROW_ON_ERROR` on/off; queue-time errors and WATCH-aborted transactions as distinct scenarios.
- Pipeline containing MULTI/EXEC, plus a failing SELECT that must restore the tracked database.
- A malformed later result after several successful conversions, then explicit cleanup/destruction and a fresh request.
- A correctly formed invalidation PUSH within EXEC, plus the required following ordinary results. This last case needs a structured reply/conversation fixture; the existing focused EXEC editor does not insert PUSH values.

Removal can make Relay read an additional frame while looking for a missing result. Bound client read timeouts. `TRANSPORT EXTRA` is useful for exploring that read, but its fixed `+EVILRESP` marker is not a substitute for a command-appropriate trailing result.

**5. Use existing transport and topology controls with explicit client recovery settings.**

The constant, uniform, exponential, full-jitter and decorrelated-jitter backoff functions are uncalled. Their option setters are also uncalled. [relayRespCmdSendDeadline](/home/mike/dev/relay-dev/relay/src/commands.c:15835) requires both a communication failure and suitable retry configuration to reach these paths.

Sweep the client retry count, each supported backoff algorithm, and small bounded base/cap values. Combine them with one fault family at a time:

| Fault | What it can exercise |
| --- | --- |
| `FAULT CLOSE` / `RESET AT BEFORE` | Recovery where evilresp did not forward the selected command |
| `AT AFTER` | Recovery after an upstream operation may already have executed; use counter/write workloads to observe duplicate execution |
| `AT bytes` / `TRUNCATE bytes` | Partial header, payload, aggregate and terminator cleanup |
| `FAULT CLOSE AT REPLY` | Successful response followed by replacement of a closed connection, including persistent reuse |
| Explicit `FAULT STALL` | Read timeout and deadline budget exhaustion |
| `EXTRA 1` | Reply/command misalignment across subsequent operations |
| Focused MOVED/ASK with SELF/NEXT/REPLICA | Redirect loops, ASKING, replica selection, retry exhaustion and recovery |

CHUNKS specifies proxy writes; it cannot guarantee individual client reads or TCP packets. Reliable short-read state-machine tests need a controlled peer/read shim. TCP reset after writing a complete reply also does not guarantee that the client received the reply.

For cluster tests, configure every participating connection and preserve correct key positions. `UNTIL` is a global absolute command-index cutoff, and ASKING/other ordinary commands can advance it. A primary with **at least two replicas** is needed to exercise “other replica” choices such as the uncalled `randomOtherReplica` at [cluster.c:2044](/home/mike/dev/relay-dev/relay/src/cluster.c:2044).

One current limitation matters for repeated failures: Relay can reconnect and retry inside a single PHP method. The hook runs around method invocations, while the new proxy connection starts non-evil. Existing setup can reliably inject the initial failure, but should not be assumed to inject a whole sequence of internal retry failures. Use a dedicated scripted peer for that experiment, or design a separate explicitly selected test-listener policy; do not silently change the per-connection defaults.

Use client-facing faults for these campaigns. evilresp now converts an upstream disconnect into an ordinary error reply while retaining the client connection; killing the upstream does not necessarily force Relay down its socket-reconnect path.

**6. Add an asynchronous invalidation fixture and a multi-request worker.**

This is the clearest substantial coverage area that today's ordinary request/reply model cannot adequately reach.

`reader.c` has 193 missing lines. Its attach/feed/parse/next functions are all uncalled. It is **not Relay's general hiredis reply parser**. It recognizes invalidation messages, including the literal header `>2\r\n$10\r\ninvalidate\r\n`. [relayReaderInvalidationsPoll](/home/mike/dev/relay-dev/relay/src/relay.c:3589) uses it from the SIGIO path. [relayCanHandleSigio](/home/mike/dev/relay-dev/relay/src/relay.c:3412) requires no active PHP request and no shutdown; the handler also requires a persistent connection with an admitted writer lease.

Use a persistent PHP worker serving multiple requests, such as a controlled FPM fixture. Request A warms cached data and leaves its persistent connection alive. Between requests, another client modifies the data or a scripted peer delivers invalidation bytes. Request B reads it again and verifies stale data was discarded. Sleeping inside a single active CLI request does not establish the required state.

Start with valid invalidations for one key, multiple keys, an empty list, and whole-database invalidation. Then vary header spelling/type, array lengths, negative lengths, missing CRLF, key payloads, and EOF/reset in each parser state. Test buffer-boundary behavior around the configured **64 KiB** reader capacity, accounting for message overhead and consumption, not just key length. Retain accepted valid sequences to reach cache deletion, broadcast and event delivery; a rejected header alone does not cover those operations.

During an active request, separately test the normal PUSH callback and user invalidation listeners. The existing snapshot already covers lines in that callback, whereas the idle reader is nearly untouched. These are different execution paths.

evilresp currently processes one command and one upstream frame at a time and documents that unsolicited PUSH/Pub/Sub conversations are unsupported. Its generator's violation PUSH is `message`-shaped, not a valid invalidation sequence, and `EXTRA` only appends simple status replies. A future asynchronous capability needs to route sideband frames independently and preserve ordinary response matching. Use explicit event ordering/sequence numbers in reproduction records; do not feed arrival timing into mutation RNGs. This is a larger project than adding another frame type.

**7. Separate cluster bootstrap coverage from routing mutations.**

`relayClusterInitSlots`, `validateClusterSlotReply`, `validateClusterSlotNodes`, `validateClusterSlotNode`, and `clusterSlotsEndpoint` are all uncalled. The cause has a concrete gate: [relayClusterInit](/home/mike/dev/relay-dev/relay/src/cluster.c:2700) chooses SLOTS when the HELLO version is below `7.0.0`, otherwise SHARDS. It does not simply try SLOTS after any SHARDS failure. A topology cache hit can bypass discovery entirely.

First use an appropriate older-server fixture, or a coherent scripted handshake reporting an older version, with a cold topology cache. Then test slot ranges, missing nodes, duplicate IDs, port types/ranges, optional hostname/IP metadata, primary/replica relationships, and partial-initialization cleanup. For SHARDS, preserve valid nodes while varying slot gaps/overlaps, roles, health, and slotless orphan replicas.

Normal evilresp deliberately protects CLUSTER SLOTS/SHARDS/NODES and cannot mutate bootstrap with an INCLUDE override. Keep that invariant. Use a dedicated discovery fixture for malformed topology, rather than weaken bootstrap in ordinary fuzzing. The default HELLO exclusion and configuration-after-construction hook also make it unsuitable for rewriting the initial version response in this experiment.

**8. Exercise codecs with valid inner payloads, and account for deliberately disabled features.**

`pack.c` is already comparatively well covered. All three uncalled functions are MessagePack availability/serialize/unserialize helpers, and the current runner explicitly installs a [guard rejecting MessagePack serializer selection](/home/mike/dev/relay-dev/relay/phpredis-client-fuzzer/hooks/no-msgpack.php:1). Additional random bytes cannot activate a serializer the workload never selects. A separately configured MessagePack campaign is the direct way to measure that gap.

For PHP serialization, igbinary, JSON, LZF, LZ4 and ZSTD, first store values through the selected codec and read them successfully. Then change a payload length/reference/type field while preserving a valid surrounding bulk string and enough inner structure to pass initial recognition. Include late truncation of the **inner** payload with correct RESP lengths, and run raw and typed calls separately. [relayUnpackEx](/home/mike/dev/relay-dev/relay/src/pack.c:253) also has numeric bypass behavior below 512 bytes when PACK_IGNORE_NUMBERS is enabled; explicitly test 511/512/513-byte boundaries and numeric/non-numeric strings.

For cache/HLL/codec size coverage, prefer real large values and bounded edits to them before simply raising all generator limits. Larger advertised lengths mainly exercise rejection/allocation paths; they do not produce a valid large data structure.

**9. Expand API workloads where the network cannot choose the code path.**

There are **1,353 uncovered executable lines out of 1,353** in `commands.c:12962–15199`, spanning subscription argument handling, JSON commands, and search commands. Add the relevant typed APIs and valid arguments before counting on mutated replies. A module-capable upstream supplies realistic successful responses; a scripted valid reply can exercise client parsing where an upstream module is unavailable. Capability discovery and client-side validation still need to permit the call. These feature-specific builders will not be covered by raw GET chaos.

Other substantial areas need their own workloads:

| Area | Required driver |
| --- | --- |
| `Relay\Table` | Direct table construction, reads/writes, iteration, value conversion, TTL, capacity and cleanup tests |
| `Relay\Sentinel` | Sentinel API construction and commands; specialized valid/malformed replies. Existing evilresp Relay/Cluster hook does not configure Sentinel objects |
| PHP sessions | Configure session handler and save path, run session start/read/write/destroy across requests, vary locking and faults; session-owned connections need a suitable fixture |
| Pub/Sub | Typed subscribe APIs and callback-context workload; rawCommand explicitly rejects protected subscription commands. Use the existing subscription runner for ordinary traffic, then an asynchronous fault fixture |
| Adaptive caching / `cms.c` | Explicitly configure Relay's adaptive cache and drive its activity/admission decisions; this is distinct from merely invoking Redis `CMS.*` |
| `shmalloc.c`, leases, locks, reclamation | Sustained admitted cache activity, memory pressure, writer contention and release; current coverage script already varies many memory settings, so measure incremental value |
| TLS | TLS-capable controlled endpoints and connection options; evilresp's TCP/Unix endpoint handling does not itself provide TLS termination |
| Heartbeat, logging, startup, signals | Dedicated runtime/configuration tests, kept separate from the RESP mutation score |

Do not target all of `reply.c` as if it represented fresh network-parser coverage. `relayNativeReplyToZVal` is uncalled and has no external callers in the inspected source—only its definition and recursive calls. Most of that function cannot be reached by selecting more reply types through the current public paths. Another uncovered line, [reply.c:209](/home/mike/dev/relay-dev/relay/src/reply.c:209), requires Valgrind and a finite double. It is a runtime gate. Similarly, alternate CPU/hash implementations and panic/assert paths should be assessed separately rather than treated as routine mutation goals.

**10. Run focused experiments before implementing a broad new mode.**

The following settings already exist. Send each setup on the **same Relay connection** that will issue the typed target command, after successful bootstrap and data preparation. They are not separate redis-cli setup sessions. Use a fresh connection/profile to avoid retained configuration surprises.

For validly framed scalar mutations on populated collections:

```text
DEBUG EVIL MODE RESET
DEBUG EVIL SEED 1234
DEBUG EVIL TOPOLOGY OFF
DEBUG EVIL TRANSPORT OFF
DEBUG EVIL EXEC OFF
DEBUG EVIL CANONICALIZE NONE
DEBUG EVIL GENERATOR PROTOCOL RESP3 CORPUS BOUNDARY VIOLATIONS OFF
DEBUG EVIL STRATEGY PRESERVE
DEBUG EVIL MUTATIONS ONE
DEBUG EVIL FRAMING OFF
DEBUG EVIL INCLUDE XREAD XREADGROUP XCLAIM XAUTOCLAIM ZRANGE ZRANDMEMBER HMGET
DEBUG EVIL MODE MUTATE PROBABILITY 10
```

Match the generator protocol to the actual client connection; this command does not negotiate RESP3. This is the baseline preserving structure, not a substitute for the proposed path/type edits. Use separate seeded `REPLACE` runs to measure what current replacement can reach. For caching/order experiments, `CANONICALIZE NONE` also avoids default sorting removing ordering cases.

For EXEC cardinality testing, after a fresh reset/profile and before entering MULTI:

```text
DEBUG EVIL TOPOLOGY OFF
DEBUG EVIL TRANSPORT OFF
DEBUG EVIL INCLUDE EXEC
DEBUG EVIL FRAMING OFF
DEBUG EVIL MODE MUTATE PROBABILITY 0
DEBUG EVIL EXEC REMOVE PROBABILITY 100
```

Repeat separately with DUPLICATE and SWAP. A selected focused EXEC edit replaces generic value/framing mutation. Empty EXEC arrays cannot be edited, and SWAP needs unequal elements.

For an isolated transport campaign on a fresh connection:

```text
DEBUG EVIL MODE OFF
DEBUG EVIL TOPOLOGY OFF
DEBUG EVIL TRANSPORT OFF
DEBUG EVIL INCLUDE GET
DEBUG EVIL TRANSPORT FAULT RESET AT AFTER PROBABILITY 100
```

Pair it with configured Relay retry/backoff options, a cache miss, and a following operation to observe recovery. Use explicit STALL settings only in a separate timeout campaign. MODE RESET invalidates other connections and preserves several independent settings; do not reset in the middle of a populated multi-connection fixture.

My suggested implementation order is:

| Priority | Change | Effort | Why first |
| --- | --- | --- | --- |
| 1 | Verify arming, add typed successful stream/ZSET/blocking seeds, separate cache-hit/miss and fault profiles | Low–medium | Can reach wholly untouched functions with existing facilities |
| 2 | Path-targeted type/aggregate edits with correct framing | Medium | Directly reaches deep semantic validation and cleanup without destroying outer structure |
| 3 | Original-payload byte edits plus codec/HLL dictionaries and actual size-boundary fixtures | Medium | Preserves the prerequisites for inner-format and cached-data execution |
| 4 | Explicit retry/backoff/replica options with existing transport/topology faults | Low–medium | Untouched strategy code already has matching fault controls |
| 5 | Scripted PUSH/EXEC sequences and multi-request persistent invalidation fixture | High | Reaches an almost unused parser and important cache lifecycle paths |
| 6 | Dedicated bootstrap, Sentinel/session and local API campaigns | Medium–high | Addresses large gaps that ordinary reply mutation cannot select |

Measure each campaign against the same build, isolated counters, initial data, and bounded work budget. Save both covered line sets and covered branch identities; compare set differences, not just percentages or subtraction of aggregate hit counts. Include a no-fault control with the same workload to distinguish gains from new commands versus gains from mutations. Do not clear live/shared `.gcda` files; collect independent runs in a disposable build/counter location and preserve this baseline.

Report newly reached functions/branches, successful formatter entries, commands reaching the proxy, cache hits/misses, early disconnects, crashes/leaks/timeouts, and new branches per unit of work. Retain coverage-increasing successful cases as well as crash reproducers. Protocol fingerprints measure byte diversity; they are not evidence of additional C execution. Coverage counters normally flush on process exit, so killed/crashed runs can be underrepresented; keep crash evidence separate and collect coverage from normal-exit reproductions where possible.

The quantitative follow-up should answer: which campaign reaches the first XREAD formatter, the first idle invalidation parse, each missing backoff algorithm, and the cached HLL routines; then which targeted mutations add new branches within them. No defensible percentage increase can be predicted from this cumulative snapshot alone.

Supporting artifacts: [all file metrics](file-coverage.csv), [all 877 uncalled function entries](uncalled-functions.csv), [preserved baseline summary](snapshot-summary.json), and [source/line-count validation](validation.json). This work changed no project code or runtime behavior. Builds, Clippy, unit tests, and live fuzz experiments were not run because the deliverable is this analysis.
