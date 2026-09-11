//! Bounded RESP generation and scalar corpora. Protocol selection constrains
//! generated trees; it does not negotiate or translate upstream replies.

use rand::Rng;
use rand_chacha::ChaCha20Rng;

use crate::error::{AppError, AppResult};
use crate::resp::Frame;

const MAX_DEPTH: usize = 3;
const MAX_ITEMS: usize = 4;
const MAX_BLOB_BYTES: usize = 4097;
const SIZES: &[usize] = &[0, 1, 31, 32, 33, 255, 256, 257, 4095, 4096, 4097];
const INTEGERS: &[i64] = &[
    i64::MIN,
    i64::MIN + 1,
    -2147483649,
    -2147483648,
    -2147483647,
    -1,
    0,
    1,
    2147483646,
    2147483647,
    2147483648,
    4294967295,
    4294967296,
    i64::MAX - 1,
    i64::MAX,
];
const DOUBLES: &[&str] = &[
    "0",
    "-0",
    "1",
    "-1",
    "4.9406564584124654e-324",
    "2.2250738585072014e-308",
    "1.7976931348623157e308",
    "-1.7976931348623157e308",
    "inf",
    "-inf",
    "nan",
];
const BIG_NUMBERS: &[&str] = &[
    "0",
    "-1",
    "9223372036854775807",
    "9223372036854775808",
    "-9223372036854775809",
    "18446744073709551615",
    "18446744073709551616",
    "340282366920938463463374607431768211455",
    "-340282366920938463463374607431768211455",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Protocol {
    Resp2,
    Resp3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Corpus {
    Boundary,
    Random,
}

#[derive(Clone, Debug)]
pub(crate) struct GeneratorConfig {
    protocol: Protocol,
    corpus: Corpus,
    violations: bool,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            protocol: Protocol::Resp2,
            corpus: Corpus::Boundary,
            violations: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    String,
    Error,
    Integer,
    Blob,
    NullBlob,
    NullArray,
    Array,
    Null,
    Boolean,
    Double,
    BigNumber,
    BulkError,
    Verbatim,
    Map,
    Set,
}

impl GeneratorConfig {
    pub(crate) fn updated(&self, argv: &[String]) -> AppResult<Self> {
        let (options, remainder) = argv.as_chunks::<2>();
        if options.is_empty() || !remainder.is_empty() {
            return Err(invalid("GENERATOR requires option/value pairs"));
        }
        let mut config = self.clone();
        let mut seen = [false; 3];
        for [option, value] in options {
            let index = match option.to_ascii_uppercase().as_str() {
                "PROTOCOL" => {
                    config.protocol = match value.to_ascii_uppercase().as_str()
                    {
                        "RESP2" => Protocol::Resp2,
                        "RESP3" => Protocol::Resp3,
                        _ => {
                            return Err(invalid(
                                "GENERATOR PROTOCOL requires RESP2 or RESP3",
                            ));
                        }
                    };
                    0
                }
                "CORPUS" => {
                    config.corpus = match value.to_ascii_uppercase().as_str() {
                        "BOUNDARY" => Corpus::Boundary,
                        "RANDOM" => Corpus::Random,
                        _ => {
                            return Err(invalid(
                                "GENERATOR CORPUS requires BOUNDARY or RANDOM",
                            ));
                        }
                    };
                    1
                }
                "VIOLATIONS" => {
                    config.violations =
                        match value.to_ascii_uppercase().as_str() {
                            "ON" => true,
                            "OFF" => false,
                            _ => {
                                return Err(invalid(
                                    "GENERATOR VIOLATIONS requires ON or OFF",
                                ));
                            }
                        };
                    2
                }
                _ => {
                    return Err(invalid(
                        "GENERATOR accepts PROTOCOL, CORPUS, and VIOLATIONS",
                    ));
                }
            };
            if seen[index] {
                return Err(invalid("duplicate GENERATOR option"));
            }
            seen[index] = true;
        }
        Ok(config)
    }

    pub(crate) fn status(&self) -> String {
        format!(
            "generator_protocol={} generator_corpus={} generator_violations={}",
            match self.protocol {
                Protocol::Resp2 => "RESP2",
                Protocol::Resp3 => "RESP3",
            },
            match self.corpus {
                Corpus::Boundary => "BOUNDARY",
                Corpus::Random => "RANDOM",
            },
            if self.violations { "ON" } else { "OFF" }
        )
    }

    fn boundary(&self, rng: &mut ChaCha20Rng) -> bool {
        self.corpus == Corpus::Boundary && rng.gen_ratio(7, 10)
    }

    fn violate(&self, rng: &mut ChaCha20Rng) -> bool {
        self.violations && rng.gen_ratio(1, 5)
    }

    pub(crate) fn frame(&self, rng: &mut ChaCha20Rng) -> Frame {
        self.frame_at(rng, 1)
    }

    fn frame_at(&self, rng: &mut ChaCha20Rng, depth: usize) -> Frame {
        if self.violate(rng) {
            return self.violation(rng, depth);
        }
        let kinds: &[Kind] = match self.protocol {
            Protocol::Resp2 => &[
                Kind::String,
                Kind::Error,
                Kind::Integer,
                Kind::Blob,
                Kind::NullBlob,
                Kind::NullArray,
                Kind::Array,
            ],
            Protocol::Resp3 => &[
                Kind::String,
                Kind::Error,
                Kind::Integer,
                Kind::Blob,
                Kind::Null,
                Kind::Boolean,
                Kind::Double,
                Kind::BigNumber,
                Kind::BulkError,
                Kind::Verbatim,
                Kind::Array,
                Kind::Map,
                Kind::Set,
            ],
        };
        let available = if depth == MAX_DEPTH {
            // Aggregate kinds are the last one (RESP2) or three (RESP3).
            kinds.len()
                - if self.protocol == Protocol::Resp2 {
                    1
                } else {
                    3
                }
        } else {
            kinds.len()
        };
        self.build(kinds[rng.gen_range(0..available)], rng, depth)
    }

    fn build(&self, kind: Kind, rng: &mut ChaCha20Rng, depth: usize) -> Frame {
        match kind {
            Kind::String => Frame::SimpleString(self.text(rng)),
            Kind::Error => {
                Frame::SimpleError(format!("ERR {}", self.text(rng)))
            }
            Kind::Integer => Frame::Integer(self.integer(rng)),
            Kind::Blob => Frame::BulkString(Some(self.blob(rng))),
            Kind::NullBlob => Frame::BulkString(None),
            Kind::NullArray => Frame::Array(None),
            Kind::Null => Frame::Null,
            Kind::Boolean => Frame::Boolean(rng.r#gen()),
            Kind::Double => Frame::Double(self.double(rng, false)),
            Kind::BigNumber => Frame::BigNumber(self.big_number(rng, false)),
            Kind::BulkError => Frame::BulkError(self.bulk_error(rng)),
            Kind::Verbatim => Frame::VerbatimString(self.verbatim(rng)),
            Kind::Array => {
                let count = self.count(rng);
                Frame::Array(Some(
                    (0..count).map(|_| self.frame_at(rng, depth + 1)).collect(),
                ))
            }
            Kind::Map => {
                let count = self.count(rng);
                Frame::Map(
                    (0..count)
                        .map(|index| {
                            (
                                Frame::BulkString(Some(
                                    format!("key:{index}").into_bytes(),
                                )),
                                self.frame_at(rng, depth + 1),
                            )
                        })
                        .collect(),
                )
            }
            Kind::Set => {
                let count = self.count(rng);
                let mut items = Vec::new();
                for index in 0..count {
                    let mut item = self.frame_at(rng, depth + 1);
                    let mut fallback = index as i64;
                    while items.contains(&item) {
                        item = Frame::Integer(fallback);
                        fallback += 1;
                    }
                    items.push(item);
                }
                Frame::Set(items)
            }
        }
    }

    fn count(&self, rng: &mut ChaCha20Rng) -> usize {
        if self.boundary(rng) {
            *pick(&[0, 1, MAX_ITEMS], rng)
        } else {
            rng.gen_range(0..=MAX_ITEMS)
        }
    }

    fn integer(&self, rng: &mut ChaCha20Rng) -> i64 {
        if self.boundary(rng) {
            *pick(INTEGERS, rng)
        } else {
            rng.r#gen()
        }
    }

    fn text(&self, rng: &mut ChaCha20Rng) -> String {
        if self.boundary(rng) {
            pick(
                &[
                    "",
                    "0",
                    "-1",
                    "2147483648",
                    "9223372036854775807",
                    "18446744073709551616",
                ],
                rng,
            )
            .to_string()
        } else {
            ascii(rng, 24)
        }
    }

    fn blob(&self, rng: &mut ChaCha20Rng) -> Vec<u8> {
        if !self.boundary(rng) {
            let len = rng.gen_range(0..=256);
            return (0..len).map(|_| rng.r#gen()).collect();
        }
        if rng.gen_ratio(1, 4) {
            return pick(BIG_NUMBERS, rng).as_bytes().to_vec();
        }
        let len = *pick(SIZES, rng);
        let pattern =
            *pick(&[b"\0".as_slice(), b"\xff", b"\r\n\0$*", b"a"], rng);
        (0..len).map(|i| pattern[i % pattern.len()]).collect()
    }

    fn double(&self, rng: &mut ChaCha20Rng, overflow: bool) -> String {
        if self.violate(rng) {
            return pick(&["not-a-number", "1e", "1.2.3"], rng).to_string();
        }
        if overflow || self.boundary(rng) {
            pick(DOUBLES, rng).to_string()
        } else {
            let value = f64::from_bits(rng.r#gen());
            if value.is_finite() {
                value.to_string()
            } else {
                "0".to_owned()
            }
        }
    }

    fn big_number(&self, rng: &mut ChaCha20Rng, overflow: bool) -> String {
        if self.violate(rng) {
            return pick(&["", "12x", "--1", "1.5"], rng).to_string();
        }
        if overflow || self.boundary(rng) {
            pick(BIG_NUMBERS, rng).to_string()
        } else {
            let sign = if rng.r#gen() { "-" } else { "" };
            format!("{sign}{}", rng.r#gen::<u128>())
        }
    }

    fn bulk_error(&self, rng: &mut ChaCha20Rng) -> Vec<u8> {
        let mut bytes = b"ERR ".to_vec();
        bytes.extend(self.blob(rng));
        bytes.truncate(MAX_BLOB_BYTES);
        bytes
    }

    fn verbatim(&self, rng: &mut ChaCha20Rng) -> Vec<u8> {
        if self.violate(rng) {
            return b"bad".to_vec();
        }
        let mut bytes = b"txt:".to_vec();
        bytes.extend(self.blob(rng));
        bytes.truncate(MAX_BLOB_BYTES);
        bytes
    }

    fn violation(&self, rng: &mut ChaCha20Rng, depth: usize) -> Frame {
        // Sideband frames occur only in this opt-in branch, and only where
        // their children fit within the generator's nesting bound.
        let sideband = depth < MAX_DEPTH;
        let kinds = if sideband { 5 } else { 3 };
        let kinds = kinds + usize::from(self.protocol == Protocol::Resp2);
        match rng.gen_range(0..kinds) {
            0 => Frame::Double("1e".to_owned()),
            1 => Frame::BigNumber("12x".to_owned()),
            2 => Frame::VerbatimString(b"bad".to_vec()),
            3 if sideband => {
                Frame::Push(vec![Frame::BulkString(Some(b"message".to_vec()))])
            }
            4 if sideband => Frame::Attribute(vec![(
                Frame::SimpleString("meta".to_owned()),
                Frame::Integer(1),
            )]),
            // Well-formed RESP3 data is also useful as a RESP2 mismatch.
            _ => Frame::Boolean(true),
        }
    }

    pub(crate) fn mutate_scalar(
        &self,
        frame: &mut Frame,
        rng: &mut ChaCha20Rng,
        overflow: bool,
    ) {
        match frame {
            Frame::Integer(value) => {
                let next = if overflow {
                    if rng.r#gen() { i64::MAX } else { i64::MIN }
                } else {
                    self.integer(rng)
                };
                *value = if next != *value {
                    next
                } else if overflow {
                    !next
                } else {
                    value.wrapping_add(1)
                };
            }
            Frame::SimpleString(value) | Frame::SimpleError(value) => {
                let mut next = if overflow {
                    overflow_text(value.as_bytes(), rng)
                } else {
                    self.text(rng)
                };
                if next == *value {
                    next.push('!');
                }
                *value = next;
            }
            Frame::Double(value) => {
                *value = different_number(self.double(rng, overflow), value);
            }
            Frame::BigNumber(value) => {
                *value =
                    different_number(self.big_number(rng, overflow), value);
            }
            Frame::BulkString(Some(bytes)) => {
                let mut next = if overflow {
                    overflow_text(bytes, rng).into_bytes()
                } else {
                    self.blob(rng)
                };
                make_different(&mut next, bytes, 0);
                *bytes = next;
            }
            Frame::BulkError(bytes) => {
                let mut next = if overflow {
                    overflow_text(bytes, rng).into_bytes()
                } else {
                    self.bulk_error(rng)
                };
                make_different(&mut next, bytes, 0);
                *bytes = next;
            }
            Frame::VerbatimString(bytes) => {
                let mut next = if overflow {
                    format!(
                        "txt:{}",
                        overflow_text(bytes.get(4..).unwrap_or_default(), rng)
                    )
                    .into_bytes()
                } else {
                    self.verbatim(rng)
                };
                make_different(&mut next, bytes, 4);
                *bytes = next;
            }
            Frame::Boolean(value) => *value = !*value,
            Frame::Inline(parts) => {
                let mut next = vec![
                    ascii(rng, 8).into_bytes(),
                    ascii(rng, 8).into_bytes(),
                ];
                if next == *parts {
                    next.push(b"x".to_vec());
                }
                *parts = next;
            }
            _ => {}
        }
    }
}

fn invalid(message: &str) -> AppError {
    AppError::EvilConfig(message.to_owned())
}

fn pick<'a, T>(items: &'a [T], rng: &mut ChaCha20Rng) -> &'a T {
    &items[rng.gen_range(0..items.len())]
}

fn ascii(rng: &mut ChaCha20Rng, max: usize) -> String {
    let len = rng.gen_range(0..=max);
    (0..len)
        .map(|_| char::from(rng.gen_range(0x21_u8..=0x7e)))
        .collect()
}

fn different_number(next: String, current: &str) -> String {
    if next != current {
        next
    } else if current == "0" {
        "1".to_owned()
    } else {
        "0".to_owned()
    }
}

fn overflow_text(current: &[u8], rng: &mut ChaCha20Rng) -> String {
    let values = [i64::MAX.to_string(), u64::MAX.to_string()];
    let index = usize::from(rng.r#gen::<bool>());
    if values[index].as_bytes() == current {
        values[1 - index].clone()
    } else {
        values[index].clone()
    }
}

fn make_different(next: &mut Vec<u8>, current: &[u8], prefix: usize) {
    if next != current {
        return;
    }
    if next.len() <= prefix {
        next.push(b'x');
    } else {
        next[prefix] ^= 1;
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;
    use crate::resp::parse_frame;

    fn assert_valid(frame: &Frame, protocol: Protocol, depth: usize) -> usize {
        assert!(depth <= MAX_DEPTH);
        let mut nodes = 1;
        match frame {
            Frame::SimpleString(s) | Frame::SimpleError(s) => {
                assert!(!s.contains(['\r', '\n']));
            }
            Frame::Integer(_) => {}
            Frame::BulkString(Some(bytes)) => {
                assert!(bytes.len() <= MAX_BLOB_BYTES)
            }
            Frame::BulkString(None) | Frame::Array(None) => {
                assert_eq!(protocol, Protocol::Resp2)
            }
            Frame::Array(Some(items)) => {
                assert!(items.len() <= MAX_ITEMS);
                for item in items {
                    nodes += assert_valid(item, protocol, depth + 1);
                }
            }
            Frame::Null | Frame::Boolean(_) => {
                assert_eq!(protocol, Protocol::Resp3)
            }
            Frame::Double(s) => {
                assert_eq!(protocol, Protocol::Resp3);
                assert!(s.parse::<f64>().is_ok(), "{s:?}");
            }
            Frame::BigNumber(s) => {
                assert_eq!(protocol, Protocol::Resp3);
                let digits = s.strip_prefix('-').unwrap_or(s);
                assert!(
                    !digits.is_empty()
                        && digits.bytes().all(|b| b.is_ascii_digit()),
                    "{s:?}"
                );
            }
            Frame::BulkError(bytes) | Frame::VerbatimString(bytes) => {
                assert_eq!(protocol, Protocol::Resp3);
                assert!(bytes.len() <= MAX_BLOB_BYTES);
                if matches!(frame, Frame::VerbatimString(_)) {
                    assert!(bytes.starts_with(b"txt:"));
                }
            }
            Frame::Map(pairs) => {
                assert_eq!(protocol, Protocol::Resp3);
                assert!(pairs.len() <= MAX_ITEMS);
                for (index, (key, value)) in pairs.iter().enumerate() {
                    assert!(
                        !pairs[..index].iter().any(|(other, _)| key == other)
                    );
                    nodes += assert_valid(key, protocol, depth + 1);
                    nodes += assert_valid(value, protocol, depth + 1);
                }
            }
            Frame::Set(items) => {
                assert_eq!(protocol, Protocol::Resp3);
                assert!(items.len() <= MAX_ITEMS);
                for (index, item) in items.iter().enumerate() {
                    assert!(!items[..index].contains(item));
                    nodes += assert_valid(item, protocol, depth + 1);
                }
            }
            Frame::Push(_) | Frame::Attribute(_) | Frame::Inline(_) => {
                panic!("unexpected generated frame: {frame:?}")
            }
        }
        nodes
    }

    #[test]
    fn generated_trees_obey_protocol_and_size_limits_recursively() {
        for protocol in [Protocol::Resp2, Protocol::Resp3] {
            for corpus in [Corpus::Boundary, Corpus::Random] {
                let config = GeneratorConfig {
                    protocol,
                    corpus,
                    violations: false,
                };
                for seed in 0..256 {
                    let frame =
                        config.frame(&mut ChaCha20Rng::seed_from_u64(seed));
                    assert!(assert_valid(&frame, protocol, 1) <= 73);
                    let bytes = frame.encode();
                    assert!(bytes.len() < 304 * 1024);
                    assert_eq!(parse_frame(&bytes).unwrap(), frame);
                }
            }
        }
    }

    #[test]
    fn scalar_mutation_keeps_numeric_and_verbatim_grammar_valid() {
        let config = GeneratorConfig {
            protocol: Protocol::Resp3,
            ..GeneratorConfig::default()
        };
        for seed in 0..128 {
            for overflow in [false, true] {
                for original in [
                    Frame::Double("1.5".to_owned()),
                    Frame::BigNumber("123".to_owned()),
                    Frame::VerbatimString(b"txt:hello".to_vec()),
                ] {
                    let mut frame = original.clone();
                    config.mutate_scalar(
                        &mut frame,
                        &mut ChaCha20Rng::seed_from_u64(seed),
                        overflow,
                    );
                    assert_ne!(frame, original);
                    assert_valid(&frame, Protocol::Resp3, 1);
                    // Force the identical proposed value; fallback must still
                    // change bytes without turning a valid value into junk.
                    let previous = frame.clone();
                    config.mutate_scalar(
                        &mut frame,
                        &mut ChaCha20Rng::seed_from_u64(seed),
                        overflow,
                    );
                    assert_ne!(frame, previous);
                    assert_valid(&frame, Protocol::Resp3, 1);
                }
            }
        }
    }

    #[test]
    fn equal_blob_fallback_respects_the_payload_cap_and_format_prefix() {
        let original = vec![0; MAX_BLOB_BYTES];
        let mut bytes = original.clone();
        make_different(&mut bytes, &original, 0);
        let mut expected = vec![0; MAX_BLOB_BYTES];
        expected[0] = 1;
        assert_eq!(bytes, expected);
        let mut verbatim = b"txt:".to_vec();
        make_different(&mut verbatim, b"txt:", 4);
        assert_eq!(verbatim, b"txt:x");
    }

    #[test]
    fn generator_options_update_atomically_and_reject_invalid_values() {
        let mut config = GeneratorConfig::default();
        config = config
            .updated(
                &["PROTOCOL", "resp3", "CORPUS", "random"].map(str::to_owned),
            )
            .unwrap();
        config = config
            .updated(&["VIOLATIONS", "on"].map(str::to_owned))
            .unwrap();
        assert_eq!(
            config.status(),
            "generator_protocol=RESP3 generator_corpus=RANDOM generator_violations=ON"
        );
        let status = config.status();
        for args in [
            vec![],
            vec!["PROTOCOL"],
            vec!["PROTOCOL", "RESP4"],
            vec!["CORPUS", "unknown"],
            vec!["VIOLATIONS", "100"],
            vec!["UNKNOWN", "OFF"],
            vec!["PROTOCOL", "RESP2", "EXTRA"],
            vec!["PROTOCOL", "RESP2", "PROTOCOL", "RESP3"],
            vec!["CORPUS", "BOUNDARY", "CORPUS", "RANDOM"],
            vec!["VIOLATIONS", "OFF", "VIOLATIONS", "ON"],
        ] {
            assert!(
                config
                    .updated(
                        &args.iter().map(|s| s.to_string()).collect::<Vec<_>>()
                    )
                    .is_err(),
                "{args:?}"
            );
            assert_eq!(config.status(), status);
        }
    }

    #[test]
    fn every_generated_type_has_an_exact_seeded_fixture() {
        use crate::evil::{EvilConfig, random_reply};
        // Seeds select every ordinary root type. Hex fixtures include binary
        // blob contents, and distinguish empty containers from RESP2 nulls.
        for (protocol, seed, expected) in [
            ("RESP2", 0, "242d310d0a"),
            ("RESP2", 1, "2b0d0a"),
            ("RESP2", 2, "2d455252202d310d0a"),
            ("RESP2", 6, "2a300d0a"),
            ("RESP2", 9, "3a323134373438333634360d0a"),
            (
                "RESP2",
                14,
                "2435360d0a330167bca7e62e1efc841bb3c625299be5897932d681f3120d7d8ce873d8fd1e687e26d32a87c558157b02581ee5f202c820410e87bfca850d0a",
            ),
            ("RESP2", 20, "2a2d310d0a"),
            (
                "RESP3",
                0,
                "3d33370d0a7478743a0d0a00242a0d0a00242a0d0a00242a0d0a00242a0d0a00242a0d0a00242a0d0a000d0a",
            ),
            ("RESP3", 1, "2d455252200d0a"),
            (
                "RESP3",
                2,
                "2433320d0affffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0d0a",
            ),
            ("RESP3", 5, "2b323134373438333634380d0a"),
            ("RESP3", 6, "7e300d0a"),
            ("RESP3", 7, "5f0d0a"),
            (
                "RESP3",
                8,
                "283334303238323336363932303933383436333436333337343630373433313736383231313435350d0a",
            ),
            (
                "RESP3",
                18,
                "2c322e32323530373338353835303732303134652d3330380d0a",
            ),
            ("RESP3", 19, "2a300d0a"),
            ("RESP3", 23, "23740d0a"),
            (
                "RESP3",
                28,
                "25310d0a24350d0a6b65793a300d0a2a340d0a2b31383434363734343037333730393535313631360d0a5f0d0a3a343239343936373239360d0a5f0d0a",
            ),
            (
                "RESP3",
                33,
                "2132340d0a455252202d393232333337323033363835343737353830390d0a",
            ),
            ("RESP3", 50, "3a2d323134373438333634390d0a"),
        ] {
            let mut config = EvilConfig::default();
            config
                .apply_debug_command(
                    &["DEBUG", "EVIL", "GENERATOR", "PROTOCOL", protocol]
                        .map(str::to_owned),
                )
                .unwrap();
            config.seed = seed;
            let reply = random_reply(&config, 9, "command");
            assert_eq!(
                reply.bytes,
                hex::decode(expected).unwrap(),
                "{protocol} seed={seed}"
            );
            assert_eq!(reply.bytes, random_reply(&config, 9, "command").bytes);
        }
    }

    #[test]
    fn preserve_bulk_mutation_exercises_real_buffer_boundaries() {
        use crate::evil::{EvilConfig, mutate_reply};
        let original = Frame::BulkString(Some(b"upstream".to_vec()));
        // Seeds select zero, one byte, and the three sizes around 4 KiB.
        for (seed, size, pattern) in [
            (1, 4095, b"a".as_slice()),
            (2, 1, b"\r\n\0$*"),
            (6, 4097, b"a"),
            (8, 4096, b"\r\n\0$*"),
            (11, 0, b"a"),
        ] {
            let mut config = EvilConfig::default();
            for args in [
                ["DEBUG", "EVIL", "MODE", "MUTATE"],
                ["DEBUG", "EVIL", "MUTATIONS", "ONE"],
                ["DEBUG", "EVIL", "FRAMING", "OFF"],
            ] {
                config
                    .apply_debug_command(&args.map(str::to_owned))
                    .unwrap();
            }
            config.seed = seed;
            let expected = Frame::BulkString(Some(
                (0..size).map(|i| pattern[i % pattern.len()]).collect(),
            ));
            let reply =
                mutate_reply(&config, 9, "command", "upstream", &original);
            assert_eq!(reply.bytes, expected.encode());
            assert_eq!(reply.mutations.len(), 1);
            assert_eq!(reply.mutations[0].path, "root");
        }
    }

    #[test]
    fn protocol_and_conversation_violations_require_opt_in() {
        use crate::evil::{EvilConfig, random_reply};
        // These seeds explicitly select each violation branch, including
        // a well-formed RESP3 boolean under the RESP2 profile.
        for (protocol, seed, expected) in [
            ("RESP2", 4, "#t\r\n"),
            ("RESP2", 5, ",1e\r\n"),
            ("RESP2", 7, "=3\r\nbad\r\n"),
            ("RESP2", 13, ">1\r\n$7\r\nmessage\r\n"),
            ("RESP2", 27, "(12x\r\n"),
            ("RESP2", 35, "|1\r\n+meta\r\n:1\r\n"),
            ("RESP3", 4, "|1\r\n+meta\r\n:1\r\n"),
            ("RESP3", 5, ",1e\r\n"),
            ("RESP3", 7, "=3\r\nbad\r\n"),
            ("RESP3", 11, ">1\r\n$7\r\nmessage\r\n"),
            ("RESP3", 27, "(12x\r\n"),
        ] {
            let mut config = EvilConfig::default();
            config
                .apply_debug_command(
                    &[
                        "DEBUG",
                        "EVIL",
                        "GENERATOR",
                        "PROTOCOL",
                        protocol,
                        "VIOLATIONS",
                        "ON",
                    ]
                    .map(str::to_owned),
                )
                .unwrap();
            config.seed = seed;
            assert_eq!(
                random_reply(&config, 9, "command").bytes,
                expected.as_bytes()
            );
            config
                .apply_debug_command(
                    &["DEBUG", "EVIL", "GENERATOR", "VIOLATIONS", "OFF"]
                        .map(str::to_owned),
                )
                .unwrap();
            let frame = parse_frame(&random_reply(&config, 9, "command").bytes)
                .unwrap();
            assert_valid(
                &frame,
                if protocol == "RESP2" {
                    Protocol::Resp2
                } else {
                    Protocol::Resp3
                },
                1,
            );
        }
    }

    #[test]
    fn violations_do_not_bypass_generation_bounds() {
        fn count(frame: &Frame, depth: usize) -> usize {
            assert!(depth <= MAX_DEPTH);
            let mut nodes = 1;
            match frame {
                Frame::Array(Some(items))
                | Frame::Set(items)
                | Frame::Push(items) => {
                    assert!(items.len() <= MAX_ITEMS);
                    for item in items {
                        nodes += count(item, depth + 1);
                    }
                }
                Frame::Map(items) | Frame::Attribute(items) => {
                    assert!(items.len() <= MAX_ITEMS);
                    for (key, value) in items {
                        nodes +=
                            count(key, depth + 1) + count(value, depth + 1);
                    }
                }
                Frame::BulkString(Some(bytes))
                | Frame::BulkError(bytes)
                | Frame::VerbatimString(bytes) => {
                    assert!(bytes.len() <= MAX_BLOB_BYTES)
                }
                _ => {}
            }
            nodes
        }
        for protocol in [Protocol::Resp2, Protocol::Resp3] {
            let config = GeneratorConfig {
                protocol,
                violations: true,
                ..GeneratorConfig::default()
            };
            for seed in 0..256 {
                let frame = config.frame(&mut ChaCha20Rng::seed_from_u64(seed));
                assert!(count(&frame, 1) <= 73);
                assert!(frame.encode().len() < 304 * 1024);
            }
        }
    }
}
