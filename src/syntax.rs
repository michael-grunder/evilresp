//! Lexical RESP faults for `FRAMING SYNTAX`. The typed tree is unchanged;
//! only how one frame is spelled on the wire differs: a respelled number, a
//! wrong line or blob-body terminator, or a substituted type byte.
//!
//! Many spellings are value-preserving for lenient parsers (`+5`, `005`,
//! `5\0`) yet invalid for strict ones, while others (`0x5`, empty) parse as
//! a different value under `atoi`/`strtol`. Both kinds of disagreement are
//! what client parsers tend to get wrong.

use rand::RngExt;
use rand_chacha::ChaCha20Rng;

use crate::error::{AppError, AppResult};
use crate::evil::{
    AppliedMutation, MutatedReply, MutationDepth, MutationKind,
    SyntaxCorruption, SyntaxMutation,
};
use crate::framing::{FaultOptions, should_apply, visit};
use crate::resp::{Frame, WireOverride};

const KINDS: [SyntaxCorruption; 4] = [
    SyntaxCorruption::Number,
    SyntaxCorruption::Terminator,
    SyntaxCorruption::Body,
    SyntaxCorruption::Type,
];

/// Header-line terminators that replace `\r\n`.
const TERMINATORS: [(&str, &[u8]); 6] = [
    ("lf", b"\n"),
    ("cr", b"\r"),
    ("cr_cr_lf", b"\r\r\n"),
    ("lf_cr", b"\n\r"),
    ("missing", b""),
    ("doubled", b"\r\n\r\n"),
];

/// Blob-body terminators. `junk` and `nul` keep the byte count so parsers
/// that skip two bytes without checking them stay in sync.
const BODY_ENDS: [(&str, &[u8]); 7] = [
    ("missing", b""),
    ("lf", b"\n"),
    ("cr", b"\r"),
    ("lf_cr", b"\n\r"),
    ("junk", b"!!"),
    ("nul", b"\0\0"),
    ("doubled", b"\r\n\r\n"),
];

/// Type bytes that no RESP version defines.
const UNKNOWN_TYPES: [u8; 5] = [b'@', b'\0', 0xff, b' ', b'\r'];

/// Interchangeable type bytes: each family shares a header shape, so a
/// substitute is plausible yet changes how children or bodies are read.
const TYPE_FAMILIES: [&[u8]; 3] = [b"*~>%|", b"$!=", b"+-:,(#_"];

const NUMBER_VARIANTS: [&str; 11] = [
    "plus",
    "leading_zeros",
    "zero_padded",
    "leading_space",
    "trailing_space",
    "empty",
    "trailing_junk",
    "trailing_nul",
    "hex",
    "decimal",
    "exponent",
];

/// Width of `zero_padded` numbers, beyond any 64-bit decimal buffer.
const PADDED_DIGITS: usize = 80;

#[derive(Clone, Debug)]
pub(crate) struct SyntaxConfig {
    options: FaultOptions<SyntaxCorruption>,
}

impl SyntaxConfig {
    pub(crate) fn parse(argv: &[String]) -> AppResult<Self> {
        let options = FaultOptions::parse("SYNTAX", argv, |value| {
            if value.eq_ignore_ascii_case("RANDOM") {
                return Ok(None);
            }
            KINDS
                .into_iter()
                .find(|kind| value.eq_ignore_ascii_case(kind_name(*kind)))
                .map(Some)
                .ok_or_else(|| {
                    AppError::EvilConfig(
                        "KIND requires RANDOM, NUMBER, TERMINATOR, BODY, or TYPE"
                            .to_owned(),
                    )
                })
        })?;
        Ok(Self { options })
    }

    pub(crate) fn status(&self) -> String {
        self.options
            .status("SYNTAX", self.options.kind.map(kind_name))
    }

    fn allows(&self, kind: SyntaxCorruption) -> bool {
        self.options.kind.is_none_or(|selected| selected == kind)
    }
}

fn kind_name(kind: SyntaxCorruption) -> &'static str {
    match kind {
        SyntaxCorruption::Number => "NUMBER",
        SyntaxCorruption::Terminator => "TERMINATOR",
        SyntaxCorruption::Body => "BODY",
        SyntaxCorruption::Type => "TYPE",
    }
}

fn applies(kind: SyntaxCorruption, frame: &Frame) -> bool {
    match kind {
        SyntaxCorruption::Number => numeric_text(frame).is_some(),
        SyntaxCorruption::Terminator | SyntaxCorruption::Type => {
            frame.type_byte().is_some()
        }
        SyntaxCorruption::Body => matches!(
            frame,
            Frame::BulkString(Some(_))
                | Frame::BulkError(_)
                | Frame::VerbatimString(_)
        ),
    }
}

/// Canonical text of an integer value or length header.
fn numeric_text(frame: &Frame) -> Option<String> {
    match frame {
        Frame::Integer(value) => Some(value.to_string()),
        _ => frame.declared_length().map(|length| length.to_string()),
    }
}

/// Select one eligible frame (depth weighted, honoring the target), then
/// one applicable kind, then one variant. Draw order is fixed.
pub(crate) fn mutate(
    frame: &Frame,
    config: &SyntaxConfig,
    depth: MutationDepth,
    rng: &mut ChaCha20Rng,
) -> Option<MutatedReply> {
    let options = &config.options;
    if !should_apply(options.probability, rng) {
        return None;
    }
    let eligible = |frame: &Frame, path: &str| {
        options.target.matches(path)
            && KINDS
                .into_iter()
                .any(|kind| config.allows(kind) && applies(kind, frame))
    };
    let mut total = 0_u128;
    visit(frame, "root", 0, &mut |frame, path, level| {
        if eligible(frame, path) {
            total += depth.weight(level);
        }
    });
    if total == 0 {
        return None;
    }
    let mut remaining = rng.random_range(0..total);
    let mut index = 0;
    let mut selected = None;
    visit(frame, "root", 0, &mut |frame, path, level| {
        if selected.is_none() && eligible(frame, path) {
            let weight = depth.weight(level);
            if remaining < weight {
                selected = Some((index, path.to_owned(), frame.clone()));
            } else {
                remaining -= weight;
            }
        }
        index += 1;
    });
    // Invariant: the second pass visits the same frames as the first.
    let (index, path, target) = selected.expect("weighted frame selection");

    let kinds = KINDS
        .into_iter()
        .filter(|kind| config.allows(*kind) && applies(*kind, &target))
        .collect::<Vec<_>>();
    let kind = kinds[rng.random_range(0..kinds.len())];
    let fault = corrupt(&target, kind, rng);
    Some(MutatedReply {
        bytes: frame.encode_with_override(index, fault.wire()),
        mutations: vec![AppliedMutation {
            path,
            kind: MutationKind::WrongSyntax,
            length: None,
            syntax: Some(SyntaxMutation {
                kind,
                variant: fault.variant,
                original_hex: hex::encode(&fault.original),
                replacement_hex: hex::encode(&fault.replacement),
            }),
            exec: None,
        }],
    })
}

struct Fault {
    kind: SyntaxCorruption,
    variant: &'static str,
    original: Vec<u8>,
    replacement: Vec<u8>,
}

impl Fault {
    fn wire(&self) -> WireOverride<'_> {
        let bytes = Some(self.replacement.as_slice());
        let mut wire = WireOverride::default();
        match self.kind {
            SyntaxCorruption::Number => wire.header = bytes,
            SyntaxCorruption::Terminator => wire.line_end = bytes,
            SyntaxCorruption::Body => wire.body_end = bytes,
            SyntaxCorruption::Type => wire.prefix = Some(self.replacement[0]),
        }
        wire
    }
}

fn corrupt(
    frame: &Frame,
    kind: SyntaxCorruption,
    rng: &mut ChaCha20Rng,
) -> Fault {
    let pick = |rng: &mut ChaCha20Rng, table: &[(&'static str, &[u8])]| {
        let (variant, bytes) = table[rng.random_range(0..table.len())];
        (variant, bytes.to_vec())
    };
    let (variant, original, replacement) = match kind {
        SyntaxCorruption::Number => {
            // Invariant: only frames with numeric text are eligible.
            let text = numeric_text(frame).expect("numeric frame");
            let variant =
                NUMBER_VARIANTS[rng.random_range(0..NUMBER_VARIANTS.len())];
            let replacement = respell(&text, variant);
            (variant, text.into_bytes(), replacement)
        }
        SyntaxCorruption::Terminator => {
            let (variant, bytes) = pick(rng, &TERMINATORS);
            (variant, b"\r\n".to_vec(), bytes)
        }
        SyntaxCorruption::Body => {
            let (variant, bytes) = pick(rng, &BODY_ENDS);
            (variant, b"\r\n".to_vec(), bytes)
        }
        SyntaxCorruption::Type => {
            // Invariant: only frames with a type byte are eligible.
            let original = frame.type_byte().expect("typed frame");
            let family = TYPE_FAMILIES
                .iter()
                .find(|family| family.contains(&original))
                .map(|family| {
                    family
                        .iter()
                        .copied()
                        .filter(|byte| *byte != original)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let (variant, choices) = if rng.random_bool(0.5) {
                ("confusable", family)
            } else {
                ("unknown", UNKNOWN_TYPES.to_vec())
            };
            let byte = choices[rng.random_range(0..choices.len())];
            (variant, vec![original], vec![byte])
        }
    };
    Fault {
        kind,
        variant,
        original,
        replacement,
    }
}

/// Spell a canonical decimal integer in a non-canonical way. Every variant
/// differs from the canonical text.
fn respell(text: &str, variant: &str) -> Vec<u8> {
    let (sign, digits) = match text.strip_prefix('-') {
        Some(digits) => ("-", digits),
        None => ("", text),
    };
    let spelled = match variant {
        "plus" => format!("+{text}"),
        "leading_zeros" => format!("{sign}00{digits}"),
        "zero_padded" => format!("{sign}{digits:0>PADDED_DIGITS$}"),
        "leading_space" => format!(" {text}"),
        "trailing_space" => format!("{text} "),
        "empty" => String::new(),
        "trailing_junk" => format!("{text}x"),
        "trailing_nul" => format!("{text}\0"),
        "hex" => {
            // Invariant: canonical text came from an i128 or i64.
            let value = digits.parse::<u128>().expect("decimal digits");
            format!("{sign}0x{value:x}")
        }
        "decimal" => format!("{text}.0"),
        "exponent" => format!("{text}e0"),
        _ => unreachable!("unknown number variant {variant}"),
    };
    spelled.into_bytes()
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use serde_json::json;

    use super::*;
    use crate::evil::{EvilConfig, MutationCount, mutate_reply};
    use crate::mutation;
    use crate::resp::parse_frame;

    fn config(syntax: &[&str]) -> EvilConfig {
        let mut config = EvilConfig::default();
        for command in [
            &["MODE", "MUTATE", "PROBABILITY", "0"][..],
            &[&["FRAMING", "SYNTAX"][..], syntax].concat(),
        ] {
            let argv = ["DEBUG", "EVIL"]
                .iter()
                .chain(command)
                .map(|arg| (*arg).to_owned())
                .collect::<Vec<_>>();
            config.apply_debug_command(&argv).unwrap();
        }
        config
    }

    fn run(bytes: &[u8], config: &EvilConfig, seed: u64) -> MutatedReply {
        mutation::mutate(
            &parse_frame(bytes).unwrap(),
            config,
            &mut ChaCha20Rng::seed_from_u64(seed),
        )
    }

    /// Run every seed in `0..64` and collect distinct outputs.
    fn outputs(bytes: &[u8], config: &EvilConfig) -> Vec<Vec<u8>> {
        let mut seen = (0..64)
            .map(|seed| run(bytes, config, seed).bytes)
            .collect::<Vec<_>>();
        seen.sort();
        seen.dedup();
        seen
    }

    #[test]
    fn respell_covers_every_variant_and_never_matches_canonical() {
        let expected = [
            ("plus", "+5", "+-12"),
            ("leading_zeros", "005", "-0012"),
            ("zero_padded", "", ""),
            ("leading_space", " 5", " -12"),
            ("trailing_space", "5 ", "-12 "),
            ("empty", "", ""),
            ("trailing_junk", "5x", "-12x"),
            ("trailing_nul", "5\0", "-12\0"),
            ("hex", "0x5", "-0xc"),
            ("decimal", "5.0", "-12.0"),
            ("exponent", "5e0", "-12e0"),
        ];
        assert_eq!(expected.len(), NUMBER_VARIANTS.len());
        for (variant, five, minus_twelve) in expected {
            let positive = respell("5", variant);
            let negative = respell("-12", variant);
            assert_ne!(positive, b"5", "{variant}");
            assert_ne!(negative, b"-12", "{variant}");
            if variant == "zero_padded" {
                assert_eq!(positive.len(), PADDED_DIGITS);
                assert!(positive.ends_with(b"05"));
                assert_eq!(negative.len(), PADDED_DIGITS + 1);
                assert!(
                    negative.starts_with(b"-000") && negative.ends_with(b"12")
                );
            } else {
                assert_eq!(positive, five.as_bytes(), "{variant}");
                assert_eq!(negative, minus_twelve.as_bytes(), "{variant}");
            }
        }
        // Lengths beyond u64 still respell exactly.
        assert_eq!(
            respell("18446744073709551616", "hex"),
            b"0x10000000000000000"
        );
    }

    #[test]
    fn number_faults_respell_integers_and_every_length_header() {
        for (before, prefix_len, digits) in [
            (":42\r\n", 1, "42"),
            (":-7\r\n", 1, "-7"),
            ("$3\r\nfoo\r\n", 1, "3"),
            ("$-1\r\n", 1, "-1"),
            ("*-1\r\n", 1, "-1"),
            ("*1\r\n+x\r\n", 1, "1"),
            ("%1\r\n+k\r\n+v\r\n", 1, "1"),
            ("~0\r\n", 1, "0"),
            (">1\r\n+m\r\n", 1, "1"),
            ("|1\r\n+k\r\n+v\r\n", 1, "1"),
            ("!3\r\nERR\r\n", 1, "3"),
            ("=7\r\ntxt:hey\r\n", 1, "7"),
        ] {
            let config = config(&["KIND", "NUMBER", "TARGET", "root"]);
            let result = run(before.as_bytes(), &config, 3);
            let syntax = result.mutations[0].syntax.as_ref().unwrap();
            assert_eq!(result.mutations[0].kind, MutationKind::WrongSyntax);
            assert_eq!(syntax.kind, SyntaxCorruption::Number);
            assert_eq!(syntax.original_hex, hex::encode(digits));
            let replacement = hex::decode(&syntax.replacement_hex).unwrap();
            assert_eq!(replacement, respell(digits, syntax.variant));
            let rest = &before[prefix_len + digits.len()..];
            let expected = [
                &before.as_bytes()[..prefix_len],
                &replacement,
                rest.as_bytes(),
            ]
            .concat();
            assert_eq!(result.bytes, expected, "{before:?}");
        }
        // Lines without numeric text are ineligible for NUMBER.
        let config = config(&["KIND", "NUMBER"]);
        for bytes in [&b"+OK\r\n"[..], b"#t\r\n", b"_\r\n", b",1.5\r\n"] {
            let result = run(bytes, &config, 0);
            assert_eq!(result.bytes, bytes);
            assert!(result.mutations.is_empty());
        }
    }

    #[test]
    fn terminator_faults_replace_only_the_selected_header_crlf() {
        let config = config(&["KIND", "TERMINATOR", "TARGET", "root.1"]);
        let original = b"*3\r\n+a\r\n$3\r\nb\r\n\r\n#t\r\n";
        let found = outputs(original, &config);
        let expected = TERMINATORS
            .iter()
            .map(|(_, end)| {
                [&b"*3\r\n+a\r\n$3"[..], end, b"b\r\n\r\n#t\r\n"].concat()
            })
            .collect::<Vec<_>>();
        assert_eq!(found.len(), expected.len());
        for bytes in expected {
            assert!(
                found.contains(&bytes),
                "{:?}",
                String::from_utf8_lossy(&bytes)
            );
        }
    }

    #[test]
    fn body_faults_change_only_blob_body_terminators() {
        let config = config(&["KIND", "BODY"]);
        // Only the bulk string is eligible; its header CRLF is untouched.
        let original = b"*2\r\n:1\r\n$2\r\nab\r\n";
        let found = outputs(original, &config);
        assert_eq!(found.len(), BODY_ENDS.len());
        for (_, end) in BODY_ENDS {
            let bytes = [&b"*2\r\n:1\r\n$2\r\nab"[..], end].concat();
            assert!(found.contains(&bytes));
        }
        for bytes in [&b"$-1\r\n"[..], b"*1\r\n:1\r\n", b"+OK\r\n"] {
            let result = run(bytes, &config, 0);
            assert_eq!(result.bytes, bytes);
            assert!(result.mutations.is_empty());
        }
    }

    #[test]
    fn type_faults_use_confusable_family_members_or_unknown_bytes() {
        let config = config(&["KIND", "TYPE", "TARGET", "root"]);
        for (original, family) in [
            (&b"*1\r\n:1\r\n"[..], &b"~>%|"[..]),
            (b"$1\r\nx\r\n", b"!="),
            (b"+OK\r\n", b"-:,(#_"),
            (b"_\r\n", b"+-:,(#"),
        ] {
            let mut confusable = Vec::new();
            let mut unknown = Vec::new();
            for seed in 0..64 {
                let result = run(original, &config, seed);
                assert_eq!(result.bytes[1..], original[1..]);
                let syntax = result.mutations[0].syntax.as_ref().unwrap();
                assert_eq!(syntax.original_hex, hex::encode(&original[..1]));
                let byte = result.bytes[0];
                match syntax.variant {
                    "confusable" => confusable.push(byte),
                    "unknown" => unknown.push(byte),
                    other => panic!("unexpected variant {other}"),
                }
            }
            assert!(confusable.iter().all(|b| family.contains(b)));
            assert!(unknown.iter().all(|b| UNKNOWN_TYPES.contains(b)));
            assert!(!confusable.is_empty() && !unknown.is_empty());
        }
    }

    #[test]
    fn random_kind_selects_only_applicable_kinds_per_frame() {
        let config = config(&["TARGET", "root"]);
        // A simple string supports only TERMINATOR and TYPE.
        let mut kinds = (0..64)
            .map(|seed| {
                run(b"+OK\r\n", &config, seed).mutations[0]
                    .syntax
                    .as_ref()
                    .unwrap()
                    .kind
            })
            .collect::<Vec<_>>();
        kinds.dedup();
        kinds.sort_by_key(|kind| kind_name(*kind));
        kinds.dedup();
        assert_eq!(
            kinds,
            [SyntaxCorruption::Terminator, SyntaxCorruption::Type]
        );
    }

    #[test]
    fn configuration_is_atomic_and_reported_in_status() {
        let mut config = config(&[
            "kind",
            "terminator",
            "PROBABILITY",
            "12.5",
            "TARGET",
            "ROOT.01.Key",
        ]);
        let status = "framing=SYNTAX framing_probability=12.50 framing_target=root.1.key framing_kind=TERMINATOR";
        assert_eq!(config.framing.status(), status);
        for invalid in [
            &["KIND", "LENGTH"][..],
            &["KIND"],
            &["KIND", "TYPE", "KIND", "BODY"],
            &["PROBABILITY", "101"],
            &["TARGET", "nope"],
            &["SHAPE", "ANY"],
        ] {
            let argv = ["DEBUG", "EVIL", "FRAMING", "SYNTAX"]
                .iter()
                .chain(invalid)
                .map(|arg| (*arg).to_owned())
                .collect::<Vec<_>>();
            assert!(config.apply_debug_command(&argv).is_err(), "{invalid:?}");
            assert_eq!(config.framing.status(), status);
        }
        let config = self::config(&[]);
        assert_eq!(
            config.framing.status(),
            "framing=SYNTAX framing_probability=100.00 framing_target=ANY framing_kind=RANDOM"
        );
    }

    #[test]
    fn ineligible_or_absent_targets_and_zero_probability_change_nothing() {
        for (bytes, settings) in [
            (&b"*1\r\n:1\r\n"[..], &["TARGET", "root.5"][..]),
            (b"*1\r\n:1\r\n", &["TARGET", "root.0", "KIND", "BODY"]),
            (b"*1\r\n:1\r\n", &["PROBABILITY", "0"]),
        ] {
            for count in [MutationCount::One, MutationCount::Many] {
                let mut config = config(settings);
                config.mutation_count = count;
                let result = run(bytes, &config, 1);
                assert_eq!(result.bytes, bytes);
                assert!(result.mutations.is_empty());
            }
        }
    }

    #[test]
    fn one_slot_prefers_syntax_and_many_combines_with_values() {
        let mut config = config(&["KIND", "TYPE", "TARGET", "root"]);
        config.probability = 100.0;
        config.mutation_count = MutationCount::One;
        let result = run(b"*1\r\n#t\r\n", &config, 7);
        assert_eq!(result.mutations.len(), 1);
        assert_eq!(result.mutations[0].kind, MutationKind::WrongSyntax);
        assert_eq!(&result.bytes[1..], b"1\r\n#t\r\n");

        config.mutation_count = MutationCount::Many;
        let result = run(b"*1\r\n#t\r\n", &config, 7);
        assert_eq!(result.mutations.len(), 2);
        assert_eq!(result.mutations[0].kind, MutationKind::RandomValue);
        assert_eq!(result.mutations[1].kind, MutationKind::WrongSyntax);
        assert_eq!(&result.bytes[1..], b"1\r\n#f\r\n");
    }

    #[test]
    fn seeded_output_and_repro_json_are_exact() {
        let original = parse_frame(b"*2\r\n$3\r\nfoo\r\n:12\r\n").unwrap();
        let config = config(&[]);
        let result = mutate_reply(&config, 9, "command", "upstream", &original);
        let repeated =
            mutate_reply(&config, 9, "command", "upstream", &original);
        assert_eq!(result.bytes, repeated.bytes);
        let json = serde_json::to_value(&result.mutations).unwrap();
        assert_eq!(json, serde_json::to_value(&repeated.mutations).unwrap());
        assert_eq!(json[0]["kind"], "wrong_syntax");
        assert!(json[0].get("length").is_none());

        // Seed 8 respells the nested integer in hex, which atoi reads as 0.
        let mut config = config.clone();
        config.seed = 8;
        let result = mutate_reply(&config, 9, "command", "upstream", &original);
        assert_eq!(result.bytes, b"*2\r\n$3\r\nfoo\r\n:0xc\r\n");
        assert_eq!(
            serde_json::to_value(&result.mutations).unwrap(),
            json!([{
                "path": "root.1",
                "kind": "wrong_syntax",
                "syntax": {
                    "kind": "number",
                    "variant": "hex",
                    "original_hex": "3132",
                    "replacement_hex": "307863",
                },
            }])
        );
    }
}
