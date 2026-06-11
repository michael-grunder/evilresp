use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use regex::Regex;
use regex::RegexBuilder;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{AppError, AppResult};
use crate::resp::Frame;

pub const DEFAULT_EXCLUDED_COMMANDS: &[&str] = &[
    "AUTH",
    "HELLO",
    "COMMAND",
    "CLIENT",
    "SELECT",
    "ASKING",
    "MULTI",
    "DISCARD",
    "SUBSCRIBE",
    "PSUBSCRIBE",
    "SSUBSCRIBE",
    "UNSUBSCRIBE",
    "QUIT",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvilMode {
    Off,
    Random,
    Mutate,
    Overflow,
}

impl EvilMode {
    pub fn as_str(self) -> &'static str {
        match self {
            EvilMode::Off => "OFF",
            EvilMode::Random => "RANDOM",
            EvilMode::Mutate => "MUTATE",
            EvilMode::Overflow => "OVERFLOW",
        }
    }
}

impl fmt::Display for EvilMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for EvilMode {
    type Err = AppError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_uppercase().as_str() {
            "OFF" => Ok(EvilMode::Off),
            "RANDOM" => Ok(EvilMode::Random),
            "MUTATE" => Ok(EvilMode::Mutate),
            "OVERFLOW" => Ok(EvilMode::Overflow),
            _ => Err(AppError::EvilConfig(format!(
                "unknown evil mode {value:?}"
            ))),
        }
    }
}

#[derive(Clone, Debug)]
pub struct EvilConfig {
    pub seed: u64,
    pub mode: EvilMode,
    pub probability: f64,
    include: Vec<FilterSpec>,
    exclude: Vec<FilterSpec>,
}

impl Default for EvilConfig {
    fn default() -> Self {
        let exclude = DEFAULT_EXCLUDED_COMMANDS
            .iter()
            .map(|command| FilterSpec::literal((*command).to_owned()))
            .collect();

        Self {
            seed: 0,
            mode: EvilMode::Off,
            probability: 0.0,
            include: Vec::new(),
            exclude,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DebugAction {
    None,
    ResetIncrementingState,
}

#[derive(Clone, Debug)]
pub struct DebugResult {
    pub frame: Frame,
    pub action: DebugAction,
}

impl EvilConfig {
    pub fn apply_debug_command(
        &mut self,
        argv: &[String],
    ) -> AppResult<DebugResult> {
        if argv.len() < 3
            || !argv[0].eq_ignore_ascii_case("DEBUG")
            || !argv[1].eq_ignore_ascii_case("EVIL")
        {
            return Err(AppError::EvilConfig(
                "expected DEBUG EVIL subcommand".to_owned(),
            ));
        }

        match argv[2].to_ascii_uppercase().as_str() {
            "SEED" => {
                let Some(seed) = argv.get(3) else {
                    return Err(AppError::EvilConfig(
                        "DEBUG EVIL SEED requires a seed".to_owned(),
                    ));
                };
                self.seed = seed.parse::<u64>().map_err(|error| {
                    AppError::EvilConfig(format!("invalid seed: {error}"))
                })?;
                Ok(DebugResult::ok())
            }
            "MODE" => {
                let Some(mode) = argv.get(3) else {
                    return Err(AppError::EvilConfig(
                        "DEBUG EVIL MODE requires a mode".to_owned(),
                    ));
                };
                if mode.eq_ignore_ascii_case("RESET") {
                    if argv.len() != 4 {
                        return Err(AppError::EvilConfig(
                            "DEBUG EVIL MODE RESET does not accept options"
                                .to_owned(),
                        ));
                    }
                    self.mode = EvilMode::Off;
                    self.probability = 0.0;
                    return Ok(DebugResult {
                        frame: Frame::SimpleString("OK".to_owned()),
                        action: DebugAction::ResetIncrementingState,
                    });
                }

                self.mode = EvilMode::from_str(mode)?;
                self.probability = if self.mode == EvilMode::Off {
                    0.0
                } else {
                    100.0
                };

                if argv.len() > 4 {
                    if argv.len() != 6
                        || !argv[4].eq_ignore_ascii_case("PROBABILITY")
                    {
                        return Err(AppError::EvilConfig(
                            "expected optional PROBABILITY <0.00-100.00>"
                                .to_owned(),
                        ));
                    }
                    self.probability = parse_probability(&argv[5])?;
                }

                Ok(DebugResult::ok())
            }
            "STATUS" => Ok(DebugResult {
                frame: Frame::BulkString(Some(self.status().into_bytes())),
                action: DebugAction::None,
            }),
            "INCLUDE" => {
                self.include = compile_filters(&argv[3..])?;
                Ok(DebugResult::ok())
            }
            "EXCLUDE" => {
                self.exclude = compile_filters(&argv[3..])?;
                Ok(DebugResult::ok())
            }
            other => Err(AppError::EvilConfig(format!(
                "unknown DEBUG EVIL subcommand {other:?}"
            ))),
        }
    }

    pub fn should_mutate_command(&self, command: Option<&str>) -> bool {
        let Some(command) = command else {
            return false;
        };

        if !self.include.is_empty()
            && !self
                .include
                .iter()
                .any(|filter| filter.matches_command(command))
        {
            return false;
        }

        !self
            .exclude
            .iter()
            .any(|filter| filter.matches_command(command))
    }

    pub fn include_filters(&self) -> Vec<String> {
        self.include.iter().map(FilterSpec::display).collect()
    }

    pub fn exclude_filters(&self) -> Vec<String> {
        self.exclude.iter().map(FilterSpec::display).collect()
    }

    pub fn status(&self) -> String {
        format!(
            "mode={} seed={} probability={:.2} include=[{}] exclude=[{}]",
            self.mode,
            self.seed,
            self.probability,
            self.include_filters().join(","),
            self.exclude_filters().join(","),
        )
    }
}

impl DebugResult {
    fn ok() -> Self {
        Self {
            frame: Frame::SimpleString("OK".to_owned()),
            action: DebugAction::None,
        }
    }
}

fn parse_probability(value: &str) -> AppResult<f64> {
    let probability = value.parse::<f64>().map_err(|error| {
        AppError::EvilConfig(format!("invalid probability: {error}"))
    })?;
    if !(0.0..=100.0).contains(&probability) {
        return Err(AppError::EvilConfig(format!(
            "probability {probability} is outside 0.00-100.00"
        )));
    }
    Ok(probability)
}

fn compile_filters(values: &[String]) -> AppResult<Vec<FilterSpec>> {
    values
        .iter()
        .map(|value| FilterSpec::compile(value))
        .collect()
}

#[derive(Clone, Debug)]
enum FilterSpec {
    Literal(String),
    Regex { source: String, regex: Regex },
    Attribute(String),
}

impl FilterSpec {
    fn compile(value: &str) -> AppResult<Self> {
        if let Some(attribute) = value.strip_prefix('@') {
            return Ok(Self::Attribute(attribute.to_ascii_lowercase()));
        }

        if looks_like_regex(value) {
            let regex = RegexBuilder::new(value)
                .case_insensitive(true)
                .build()
                .map_err(|error| {
                    AppError::EvilConfig(format!(
                        "invalid regex {value:?}: {error}"
                    ))
                })?;
            Ok(Self::Regex {
                source: value.to_owned(),
                regex,
            })
        } else {
            Ok(Self::literal(value.to_owned()))
        }
    }

    fn literal(value: String) -> Self {
        Self::Literal(value.to_ascii_uppercase())
    }

    fn matches_command(&self, command: &str) -> bool {
        match self {
            Self::Literal(value) => command.eq_ignore_ascii_case(value),
            Self::Regex { regex, .. } => regex.is_match(command),
            Self::Attribute(attribute) => {
                command_attributes(command).contains(attribute.as_str())
            }
        }
    }

    fn display(&self) -> String {
        match self {
            Self::Literal(value) => value.clone(),
            Self::Regex { source, .. } => source.clone(),
            Self::Attribute(value) => format!("@{value}"),
        }
    }
}

fn looks_like_regex(value: &str) -> bool {
    value.bytes().any(|byte| {
        matches!(
            byte,
            b'^' | b'$'
                | b'.'
                | b'*'
                | b'+'
                | b'?'
                | b'('
                | b')'
                | b'['
                | b']'
                | b'{'
                | b'}'
                | b'|'
        )
    })
}

fn command_attributes(command: &str) -> BTreeSet<&'static str> {
    let command = command.to_ascii_uppercase();
    let mut attributes = BTreeSet::new();

    match command.as_str() {
        "GET" | "MGET" | "EXISTS" | "TTL" | "PTTL" | "HGET" | "HGETALL"
        | "HMGET" | "HEXISTS" | "LRANGE" | "LLEN" | "SCARD" | "SMEMBERS"
        | "SISMEMBER" | "ZCARD" | "ZRANGE" => {
            attributes.insert("read");
        }
        "SET" | "MSET" | "DEL" | "EXPIRE" | "PEXPIRE" | "HSET" | "HMSET"
        | "HDEL" | "LPUSH" | "RPUSH" | "LPOP" | "RPOP" | "SADD" | "SREM"
        | "ZADD" | "ZREM" => {
            attributes.insert("write");
        }
        _ => {}
    }

    match command.as_str() {
        "GET" | "MGET" | "SET" | "MSET" => {
            attributes.insert("string");
        }
        "HGET" | "HGETALL" | "HMGET" | "HEXISTS" | "HSET" | "HMSET"
        | "HDEL" => {
            attributes.insert("hash");
        }
        "LRANGE" | "LLEN" | "LPUSH" | "RPUSH" | "LPOP" | "RPOP" => {
            attributes.insert("list");
        }
        "SCARD" | "SMEMBERS" | "SISMEMBER" | "SADD" | "SREM" => {
            attributes.insert("set");
        }
        "ZCARD" | "ZRANGE" | "ZADD" | "ZREM" => {
            attributes.insert("zset");
        }
        _ => {}
    }

    attributes
}

#[derive(Clone, Debug, Serialize)]
pub struct AppliedMutation {
    pub path: String,
    pub kind: MutationKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    RandomFrame,
    RandomValue,
    WrongType,
    WrongLength,
    OverflowValue,
}

#[derive(Clone, Debug)]
pub struct MutatedReply {
    pub bytes: Vec<u8>,
    pub mutations: Vec<AppliedMutation>,
}

pub fn deterministic_hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn random_reply(
    config: &EvilConfig,
    _connection_id: u64,
    command_index: u64,
    command_hash: &str,
) -> MutatedReply {
    let mut rng = rng_for(config.seed, command_index, command_hash, "");
    let frame = random_frame(&mut rng, 0);
    MutatedReply {
        bytes: frame.encode(),
        mutations: vec![AppliedMutation {
            path: "root".to_owned(),
            kind: MutationKind::RandomFrame,
        }],
    }
}

pub fn mutate_reply(
    config: &EvilConfig,
    _connection_id: u64,
    command_index: u64,
    command_hash: &str,
    upstream_hash: &str,
    upstream: &Frame,
) -> MutatedReply {
    let mut rng =
        rng_for(config.seed, command_index, command_hash, upstream_hash);
    let mut frame = upstream.clone();
    let mut mutations = Vec::new();
    mutate_frame(
        &mut frame,
        config.mode,
        config.probability,
        &mut rng,
        "root",
        &mut mutations,
    );

    let mut bytes = frame.encode();
    if should_apply(config.probability, &mut rng)
        && corrupt_first_length(&mut bytes, config.mode)
    {
        mutations.push(AppliedMutation {
            path: "root".to_owned(),
            kind: MutationKind::WrongLength,
        });
    }

    MutatedReply { bytes, mutations }
}

fn rng_for(
    seed: u64,
    command_index: u64,
    command_hash: &str,
    upstream_hash: &str,
) -> ChaCha20Rng {
    let mut digest = Sha256::new();
    digest.update(seed.to_le_bytes());
    digest.update(command_index.to_le_bytes());
    digest.update(command_hash.as_bytes());
    digest.update(upstream_hash.as_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    ChaCha20Rng::from_seed(bytes)
}

fn mutate_frame(
    frame: &mut Frame,
    mode: EvilMode,
    probability: f64,
    rng: &mut ChaCha20Rng,
    path: &str,
    mutations: &mut Vec<AppliedMutation>,
) {
    if should_apply(probability, rng) {
        let kind = mutate_one(frame, mode, rng);
        mutations.push(AppliedMutation {
            path: path.to_owned(),
            kind,
        });
    }

    match frame {
        Frame::Array(Some(items)) | Frame::Set(items) | Frame::Push(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                mutate_frame(
                    item,
                    mode,
                    probability,
                    rng,
                    &format!("{path}.{index}"),
                    mutations,
                );
            }
        }
        Frame::Map(items) | Frame::Attribute(items) => {
            for (index, (key, value)) in items.iter_mut().enumerate() {
                mutate_frame(
                    key,
                    mode,
                    probability,
                    rng,
                    &format!("{path}.{index}.key"),
                    mutations,
                );
                mutate_frame(
                    value,
                    mode,
                    probability,
                    rng,
                    &format!("{path}.{index}.value"),
                    mutations,
                );
            }
        }
        _ => {}
    }
}

fn should_apply(probability: f64, rng: &mut ChaCha20Rng) -> bool {
    probability > 0.0 && rng.gen_range(0.0..100.0) < probability
}

fn mutate_one(
    frame: &mut Frame,
    mode: EvilMode,
    rng: &mut ChaCha20Rng,
) -> MutationKind {
    if mode == EvilMode::Overflow {
        apply_overflow(frame, rng);
        return MutationKind::OverflowValue;
    }

    match rng.gen_range(0..3) {
        0 => {
            *frame = random_frame(rng, 0);
            MutationKind::WrongType
        }
        1 => {
            apply_random_value(frame, rng);
            MutationKind::RandomValue
        }
        _ => {
            *frame = random_frame(rng, 0);
            MutationKind::RandomFrame
        }
    }
}

fn apply_random_value(frame: &mut Frame, rng: &mut ChaCha20Rng) {
    match frame {
        Frame::SimpleString(value)
        | Frame::SimpleError(value)
        | Frame::Double(value)
        | Frame::BigNumber(value) => *value = random_ascii(rng, 24),
        Frame::Integer(value) => *value = rng.r#gen(),
        Frame::BulkString(Some(bytes))
        | Frame::BulkError(bytes)
        | Frame::VerbatimString(bytes) => *bytes = random_bytes(rng, 32),
        Frame::BulkString(None) => {
            *frame = Frame::BulkString(Some(random_bytes(rng, 16)))
        }
        Frame::Array(None) => {
            *frame = Frame::Array(Some(vec![random_frame(rng, 1)]))
        }
        Frame::Null => *frame = Frame::BulkString(Some(random_bytes(rng, 8))),
        Frame::Boolean(value) => *value = !*value,
        Frame::Inline(parts) => {
            *parts = vec![random_bytes(rng, 8), random_bytes(rng, 8)]
        }
        Frame::Array(Some(_))
        | Frame::Map(_)
        | Frame::Set(_)
        | Frame::Push(_)
        | Frame::Attribute(_) => {
            *frame = random_frame(rng, 0);
        }
    }
}

fn apply_overflow(frame: &mut Frame, rng: &mut ChaCha20Rng) {
    match frame {
        Frame::Integer(value) => {
            *value = if rng.r#gen() { i64::MAX } else { i64::MIN };
        }
        Frame::SimpleString(value)
        | Frame::SimpleError(value)
        | Frame::Double(value)
        | Frame::BigNumber(value) => {
            *value = if rng.r#gen() {
                i64::MAX.to_string()
            } else {
                u64::MAX.to_string()
            };
        }
        Frame::BulkString(Some(bytes))
        | Frame::BulkError(bytes)
        | Frame::VerbatimString(bytes) => {
            *bytes = if rng.r#gen() {
                i64::MAX.to_string().into_bytes()
            } else {
                u64::MAX.to_string().into_bytes()
            };
        }
        _ => *frame = Frame::Integer(i64::MAX),
    }
}

fn random_frame(rng: &mut ChaCha20Rng, depth: u8) -> Frame {
    let max_kind = if depth >= 2 { 6 } else { 8 };
    match rng.gen_range(0..max_kind) {
        0 => Frame::SimpleString(random_ascii(rng, 20)),
        1 => Frame::SimpleError(random_ascii(rng, 20)),
        2 => Frame::Integer(rng.r#gen()),
        3 => Frame::BulkString(Some(random_bytes(rng, 32))),
        4 => Frame::Null,
        5 => Frame::Boolean(rng.r#gen()),
        6 => Frame::Array(Some(vec![
            random_frame(rng, depth + 1),
            random_frame(rng, depth + 1),
        ])),
        _ => Frame::Map(vec![(
            random_frame(rng, depth + 1),
            random_frame(rng, depth + 1),
        )]),
    }
}

fn random_ascii(rng: &mut ChaCha20Rng, max_len: usize) -> String {
    let len = rng.gen_range(0..=max_len);
    (0..len)
        .map(|_| char::from(rng.gen_range(0x21_u8..=0x7e_u8)))
        .collect()
}

fn random_bytes(rng: &mut ChaCha20Rng, max_len: usize) -> Vec<u8> {
    let len = rng.gen_range(0..=max_len);
    (0..len).map(|_| rng.r#gen()).collect()
}

fn corrupt_first_length(bytes: &mut Vec<u8>, mode: EvilMode) -> bool {
    let Some(prefix) = bytes.first().copied() else {
        return false;
    };
    if !matches!(
        prefix,
        b'$' | b'*' | b'!' | b'=' | b'%' | b'~' | b'>' | b'|'
    ) {
        return false;
    }

    let Some(line_end) = bytes.windows(2).position(|window| window == b"\r\n")
    else {
        return false;
    };
    let current = std::str::from_utf8(&bytes[1..line_end])
        .ok()
        .and_then(|value| value.parse::<i64>().ok());
    let replacement = if mode == EvilMode::Overflow {
        i64::MAX
    } else {
        current.unwrap_or(0).saturating_add(1)
    };
    bytes.splice(1..line_end, replacement.to_string().bytes());
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resp::parse_frame;

    #[test]
    fn default_excludes_skip_fragile_commands() {
        let config = EvilConfig::default();
        assert!(!config.should_mutate_command(Some("HELLO")));
        assert!(!config.should_mutate_command(Some("COMMAND")));
        assert!(config.should_mutate_command(Some("GET")));
    }

    #[test]
    fn include_and_exclude_filters_compose() {
        let mut config = EvilConfig::default();
        config
            .apply_debug_command(&strings([
                "DEBUG", "EVIL", "INCLUDE", "^GET.*",
            ]))
            .unwrap();
        config
            .apply_debug_command(&strings([
                "DEBUG", "EVIL", "EXCLUDE", "GETSET",
            ]))
            .unwrap();

        assert!(config.should_mutate_command(Some("GET")));
        assert!(config.should_mutate_command(Some("GETRANGE")));
        assert!(!config.should_mutate_command(Some("GETSET")));
        assert!(!config.should_mutate_command(Some("SET")));
    }

    #[test]
    fn debug_mode_parses_probability() {
        let mut config = EvilConfig::default();
        config
            .apply_debug_command(&strings([
                "DEBUG",
                "EVIL",
                "MODE",
                "MUTATE",
                "PROBABILITY",
                "12.5",
            ]))
            .unwrap();

        assert_eq!(config.mode, EvilMode::Mutate);
        assert_eq!(config.probability, 12.5);
    }

    #[test]
    fn debug_mode_reset_turns_mode_off_and_requests_counter_reset() {
        let mut config = EvilConfig {
            seed: 1234,
            mode: EvilMode::Mutate,
            probability: 50.0,
            ..EvilConfig::default()
        };

        let result = config
            .apply_debug_command(&strings(["DEBUG", "EVIL", "MODE", "RESET"]))
            .unwrap();

        assert_eq!(config.seed, 1234);
        assert_eq!(config.mode, EvilMode::Off);
        assert_eq!(config.probability, 0.0);
        assert_eq!(result.action, DebugAction::ResetIncrementingState);
    }

    #[test]
    fn debug_mode_reset_rejects_probability() {
        let mut config = EvilConfig::default();

        let error = config
            .apply_debug_command(&strings([
                "DEBUG",
                "EVIL",
                "MODE",
                "RESET",
                "PROBABILITY",
                "100",
            ]))
            .unwrap_err();

        assert!(error.to_string().contains("does not accept options"));
    }

    #[test]
    fn mutations_are_deterministic_for_repro_tuple() {
        let config = EvilConfig {
            seed: 1234,
            mode: EvilMode::Mutate,
            probability: 100.0,
            ..EvilConfig::default()
        };

        let frame = parse_frame(b"*2\r\n$3\r\nfoo\r\n:1\r\n").unwrap();
        let first = mutate_reply(&config, 7, 9, "command", "upstream", &frame);
        let second = mutate_reply(&config, 7, 9, "command", "upstream", &frame);

        assert_eq!(first.bytes, second.bytes);
        assert!(!first.mutations.is_empty());
    }

    #[test]
    fn mutations_do_not_depend_on_connection_id() {
        let config = EvilConfig {
            seed: 1234,
            mode: EvilMode::Mutate,
            probability: 100.0,
            ..EvilConfig::default()
        };

        let frame = parse_frame(b"*2\r\n$3\r\nfoo\r\n:1\r\n").unwrap();
        let first = mutate_reply(&config, 7, 9, "command", "upstream", &frame);
        let second =
            mutate_reply(&config, 42, 9, "command", "upstream", &frame);

        assert_eq!(first.bytes, second.bytes);
        assert_eq!(first.mutations.len(), second.mutations.len());
    }

    fn strings<const N: usize>(items: [&str; N]) -> Vec<String> {
        items.into_iter().map(str::to_owned).collect()
    }
}
