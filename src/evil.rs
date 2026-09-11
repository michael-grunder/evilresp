use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use regex::Regex;
use regex::RegexBuilder;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{AppError, AppResult};
use crate::framing::FramingConfig;
use crate::generator::GeneratorConfig;
use crate::mutation;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanonicalizationMode {
    All,
    Unordered,
    None,
}

impl CanonicalizationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            CanonicalizationMode::All => "ALL",
            CanonicalizationMode::Unordered => "UNORDERED",
            CanonicalizationMode::None => "NONE",
        }
    }
}

impl fmt::Display for CanonicalizationMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for CanonicalizationMode {
    type Err = AppError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_uppercase().as_str() {
            "ALL" => Ok(CanonicalizationMode::All),
            "UNORDERED" => Ok(CanonicalizationMode::Unordered),
            "NONE" => Ok(CanonicalizationMode::None),
            _ => Err(AppError::EvilConfig(format!(
                "unknown canonicalization mode {value:?}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationStrategy {
    Preserve,
    Replace,
}

impl MutationStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preserve => "PRESERVE",
            Self::Replace => "REPLACE",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationCount {
    One,
    Many,
}

impl MutationCount {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::One => "ONE",
            Self::Many => "MANY",
        }
    }
}

#[derive(Clone, Debug)]
pub struct EvilConfig {
    pub seed: u64,
    pub mode: EvilMode,
    pub probability: f64,
    pub topology_probability: f64,
    pub canonicalization: CanonicalizationMode,
    pub strategy: MutationStrategy,
    pub mutation_count: MutationCount,
    pub(crate) framing: FramingConfig,
    pub(crate) generator: GeneratorConfig,
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
            topology_probability: 0.0,
            canonicalization: CanonicalizationMode::Unordered,
            strategy: MutationStrategy::Preserve,
            mutation_count: MutationCount::Many,
            framing: FramingConfig::Auto,
            generator: GeneratorConfig::default(),
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
                if argv.len() != 4 {
                    return Err(AppError::EvilConfig(
                        "DEBUG EVIL SEED does not accept options".to_owned(),
                    ));
                }
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

                let mode = EvilMode::from_str(mode)?;
                let mut probability =
                    if mode == EvilMode::Off { 0.0 } else { 100.0 };

                if argv.len() > 4 {
                    if argv.len() != 6
                        || !argv[4].eq_ignore_ascii_case("PROBABILITY")
                    {
                        return Err(AppError::EvilConfig(
                            "expected optional PROBABILITY <0.00-100.00>"
                                .to_owned(),
                        ));
                    }
                    probability = parse_probability(&argv[5])?;
                }

                // Commit only after every option has been validated.
                self.mode = mode;
                self.probability = probability;
                Ok(DebugResult::ok())
            }
            "GENERATOR" => {
                self.generator = self.generator.updated(&argv[3..])?;
                Ok(DebugResult::ok())
            }
            "FRAMING" => {
                self.framing = FramingConfig::parse(&argv[3..])?;
                Ok(DebugResult::ok())
            }
            "STRATEGY" => {
                if argv.len() != 4 {
                    return Err(AppError::EvilConfig(
                        "DEBUG EVIL STRATEGY requires PRESERVE or REPLACE"
                            .to_owned(),
                    ));
                }
                self.strategy =
                    match argv[3].to_ascii_uppercase().as_str() {
                        "PRESERVE" => MutationStrategy::Preserve,
                        "REPLACE" => MutationStrategy::Replace,
                        _ => return Err(AppError::EvilConfig(
                            "DEBUG EVIL STRATEGY requires PRESERVE or REPLACE"
                                .to_owned(),
                        )),
                    };
                Ok(DebugResult::ok())
            }
            "MUTATIONS" => {
                if argv.len() != 4 {
                    return Err(AppError::EvilConfig(
                        "DEBUG EVIL MUTATIONS requires ONE or MANY".to_owned(),
                    ));
                }
                self.mutation_count =
                    match argv[3].to_ascii_uppercase().as_str() {
                        "ONE" => MutationCount::One,
                        "MANY" => MutationCount::Many,
                        _ => {
                            return Err(AppError::EvilConfig(
                                "DEBUG EVIL MUTATIONS requires ONE or MANY"
                                    .to_owned(),
                            ));
                        }
                    };
                Ok(DebugResult::ok())
            }
            "CANONICALIZE" => {
                let Some(mode) = argv.get(3) else {
                    return Err(AppError::EvilConfig(
                        "DEBUG EVIL CANONICALIZE requires ALL, UNORDERED, or NONE"
                            .to_owned(),
                    ));
                };
                if argv.len() != 4 {
                    return Err(AppError::EvilConfig(
                        "DEBUG EVIL CANONICALIZE does not accept options"
                            .to_owned(),
                    ));
                }
                self.canonicalization = CanonicalizationMode::from_str(mode)?;
                Ok(DebugResult::ok())
            }
            "TOPOLOGY" => {
                let Some(probability) = argv.get(3) else {
                    return Err(AppError::EvilConfig(
                        "DEBUG EVIL TOPOLOGY requires a probability".to_owned(),
                    ));
                };
                if argv.len() != 4 {
                    return Err(AppError::EvilConfig(
                        "DEBUG EVIL TOPOLOGY does not accept options"
                            .to_owned(),
                    ));
                }
                self.topology_probability = parse_probability(probability)?;
                Ok(DebugResult::ok())
            }
            "STATUS" => {
                if argv.len() != 3 {
                    return Err(AppError::EvilConfig(
                        "DEBUG EVIL STATUS does not accept options".to_owned(),
                    ));
                }
                Ok(DebugResult {
                    frame: Frame::BulkString(Some(self.status().into_bytes())),
                    action: DebugAction::None,
                })
            }
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
            "mode={} seed={} probability={:.2} topology_probability={:.2} canonicalize={} include=[{}] exclude=[{}] strategy={} mutations={} {} {}",
            self.mode,
            self.seed,
            self.probability,
            self.topology_probability,
            self.canonicalization,
            self.include_filters().join(","),
            self.exclude_filters().join(","),
            self.strategy.as_str(),
            self.mutation_count.as_str(),
            self.framing.status(),
            self.generator.status(),
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

pub(crate) fn parse_probability(value: &str) -> AppResult<f64> {
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
        | "HMGET" | "HEXISTS" | "LRANGE" | "LLEN" | "SCARD" | "SDIFF"
        | "SINTER" | "SISMEMBER" | "SMEMBERS" | "SUNION" | "ZCARD"
        | "ZRANGE" => {
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
        "SCARD" | "SDIFF" | "SINTER" | "SISMEMBER" | "SMEMBERS" | "SUNION"
        | "SADD" | "SREM" => {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<LengthMutation>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LengthMutation {
    pub kind: LengthCorruption,
    // Strings retain exact decimal text even beyond integer/JSON ranges.
    pub original: String,
    pub replacement: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LengthCorruption {
    Shorter,
    Longer,
    Negative,
    Boundary,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    RandomFrame,
    RandomValue,
    WrongType,
    WrongLength,
    OverflowValue,
    TopologyFakeRedirection,
    TopologyWrongRedirectionKind,
    TopologyWrongSlot,
    TopologyWrongServer,
    TopologyWildSlot,
}

#[derive(Clone, Debug)]
pub struct MutatedReply {
    pub bytes: Vec<u8>,
    pub mutations: Vec<AppliedMutation>,
}

pub fn deterministic_hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn canonicalize_reply(
    mode: CanonicalizationMode,
    command: Option<&str>,
    frame: &Frame,
) -> Frame {
    let mut frame = frame.clone();
    canonicalize_reply_in_place(mode, command, &mut frame);
    frame
}

pub fn canonicalize_transaction_reply(
    mode: CanonicalizationMode,
    commands: &[String],
    frame: &Frame,
) -> Frame {
    let mut frame = frame.clone();
    let Frame::Array(Some(items)) = &mut frame else {
        return frame;
    };

    for (item, command) in items.iter_mut().zip(commands) {
        canonicalize_reply_in_place(mode, Some(command), item);
    }

    frame
}

fn canonicalize_reply_in_place(
    mode: CanonicalizationMode,
    command: Option<&str>,
    frame: &mut Frame,
) {
    match mode {
        CanonicalizationMode::All => canonicalize_all_containers(frame),
        CanonicalizationMode::Unordered => {
            canonicalize_unordered_reply(command, frame);
        }
        CanonicalizationMode::None => {}
    }
}

pub fn random_reply(
    config: &EvilConfig,
    command_index: u64,
    command_hash: &str,
) -> MutatedReply {
    let mut rng = rng_for(config.seed, command_index, command_hash, "");
    let frame = config.generator.frame(&mut rng);
    MutatedReply {
        bytes: frame.encode(),
        mutations: vec![AppliedMutation {
            path: "root".to_owned(),
            kind: MutationKind::RandomFrame,
            length: None,
        }],
    }
}

pub fn mutate_reply(
    config: &EvilConfig,
    command_index: u64,
    command_hash: &str,
    upstream_hash: &str,
    upstream: &Frame,
) -> MutatedReply {
    let mut rng =
        rng_for(config.seed, command_index, command_hash, upstream_hash);
    mutation::mutate(upstream, config, &mut rng)
}

fn canonicalize_all_containers(frame: &mut Frame) {
    match frame {
        Frame::Array(Some(items)) | Frame::Set(items) | Frame::Push(items) => {
            canonicalize_frame_items(items);
        }
        Frame::Map(items) | Frame::Attribute(items) => {
            canonicalize_frame_pairs(items);
        }
        _ => {}
    }
}

fn canonicalize_unordered_reply(command: Option<&str>, frame: &mut Frame) {
    canonicalize_unordered_containers(frame);

    let Some(command) = command else {
        return;
    };

    match command.to_ascii_uppercase().as_str() {
        "HGETALL" => canonicalize_array_pairs(frame),
        "HKEYS" | "HVALS" | "SDIFF" | "SINTER" | "SMEMBERS" | "SUNION" => {
            canonicalize_array_items(frame)
        }
        _ => {}
    }
}

fn canonicalize_unordered_containers(frame: &mut Frame) {
    match frame {
        Frame::Array(Some(items)) | Frame::Push(items) => {
            for item in items {
                canonicalize_unordered_containers(item);
            }
        }
        Frame::Map(items) | Frame::Attribute(items) => {
            canonicalize_unordered_frame_pairs(items);
        }
        Frame::Set(items) => {
            for item in items.iter_mut() {
                canonicalize_unordered_containers(item);
            }
            items.sort_by_key(sort_key);
        }
        _ => {}
    }
}

fn canonicalize_array_items(frame: &mut Frame) {
    if let Frame::Array(Some(items)) = frame {
        for item in items.iter_mut() {
            canonicalize_unordered_containers(item);
        }
        items.sort_by_key(sort_key);
    }
}

fn canonicalize_array_pairs(frame: &mut Frame) {
    let Frame::Array(Some(items)) = frame else {
        return;
    };
    for item in items.iter_mut() {
        canonicalize_unordered_containers(item);
    }

    let (chunks, remainder) = items.as_chunks::<2>();
    let mut pairs = chunks
        .iter()
        .map(|[key, value]| (key.clone(), value.clone()))
        .collect::<Vec<_>>();
    let remainder = remainder.to_vec();
    pairs.sort_by(|left, right| {
        sort_key(&left.0)
            .cmp(&sort_key(&right.0))
            .then_with(|| sort_key(&left.1).cmp(&sort_key(&right.1)))
    });

    items.clear();
    for (key, value) in pairs {
        items.push(key);
        items.push(value);
    }
    items.extend(remainder);
}

fn canonicalize_frame_items(items: &mut [Frame]) {
    for item in items.iter_mut() {
        canonicalize_all_containers(item);
    }
    items.sort_by_key(sort_key);
}

fn canonicalize_frame_pairs(items: &mut [(Frame, Frame)]) {
    for (key, value) in items.iter_mut() {
        canonicalize_all_containers(key);
        canonicalize_all_containers(value);
    }
    items.sort_by(|left, right| {
        sort_key(&left.0)
            .cmp(&sort_key(&right.0))
            .then_with(|| sort_key(&left.1).cmp(&sort_key(&right.1)))
    });
}

fn canonicalize_unordered_frame_pairs(items: &mut [(Frame, Frame)]) {
    for (key, value) in items.iter_mut() {
        canonicalize_unordered_containers(key);
        canonicalize_unordered_containers(value);
    }
    items.sort_by(|left, right| {
        sort_key(&left.0)
            .cmp(&sort_key(&right.0))
            .then_with(|| sort_key(&left.1).cmp(&sort_key(&right.1)))
    });
}

fn sort_key(frame: &Frame) -> Vec<u8> {
    frame.encode()
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
    fn mutation_controls_are_local_validated_and_preserved_by_reset() {
        let mut config = EvilConfig::default();
        assert_eq!(config.strategy, MutationStrategy::Preserve);
        assert_eq!(config.mutation_count, MutationCount::Many);
        for args in [
            ["DEBUG", "EVIL", "STRATEGY", "replace"],
            ["DEBUG", "EVIL", "MUTATIONS", "one"],
            ["DEBUG", "EVIL", "MODE", "OVERFLOW"],
            ["DEBUG", "EVIL", "MODE", "RESET"],
        ] {
            config.apply_debug_command(&strings(args)).unwrap();
        }
        assert_eq!(config.strategy, MutationStrategy::Replace);
        assert_eq!(config.mutation_count, MutationCount::One);
        assert!(config.status().contains("strategy=REPLACE mutations=ONE"));
        assert_eq!(EvilConfig::default().strategy, MutationStrategy::Preserve);
        assert_eq!(EvilConfig::default().mutation_count, MutationCount::Many);
        for args in [
            ["DEBUG", "EVIL", "STRATEGY", "preserve"],
            ["DEBUG", "EVIL", "MUTATIONS", "many"],
        ] {
            config.apply_debug_command(&strings(args)).unwrap();
        }
        assert!(config.status().contains("strategy=PRESERVE mutations=MANY"));
    }

    #[test]
    fn rejected_debug_commands_preserve_configuration() {
        let mut config = EvilConfig {
            seed: 42,
            mode: EvilMode::Overflow,
            probability: 12.5,
            topology_probability: 25.0,
            ..EvilConfig::default()
        };
        let before = config.status();
        for args in [
            vec!["MODE", "MUTATE", "PROBABILITY", "101"],
            vec!["MODE", "MUTATE", "PROBABILITY", "NaN"],
            vec!["MODE", "MUTATE", "PROBABILITY", "inf"],
            vec!["MODE", "MUTATE", "PROBABILITY", "-1"],
            vec!["MODE", "OFF", "unexpected"],
            vec!["MODE", "RANDOM", "PROBABILITY"],
            vec!["SEED", "7", "unexpected"],
            vec!["STATUS", "unexpected"],
            vec!["INCLUDE", "GET", "["],
            vec!["EXCLUDE", "SET", "["],
            vec!["STRATEGY"],
            vec!["STRATEGY", "unknown"],
            vec!["STRATEGY", "REPLACE", "extra"],
            vec!["MUTATIONS"],
            vec!["MUTATIONS", "unknown"],
            vec!["MUTATIONS", "ONE", "extra"],
        ] {
            let argv = ["DEBUG", "EVIL"]
                .into_iter()
                .chain(args)
                .map(str::to_owned)
                .collect::<Vec<_>>();
            assert!(config.apply_debug_command(&argv).is_err(), "{argv:?}");
            assert_eq!(config.status(), before, "{argv:?}");
        }
    }

    #[test]
    fn framing_configuration_is_atomic_and_survives_mode_changes() {
        let mut config = EvilConfig::default();
        assert_eq!(config.framing.status(), "framing=AUTO");
        config
            .apply_debug_command(&strings([
                "DEBUG",
                "EVIL",
                "FRAMING",
                "length",
                "kind",
                "shorter",
                "target",
                "ROOT.001.000.KEY",
                "probability",
                "12.5",
            ]))
            .unwrap();
        let status = "framing=LENGTH framing_probability=12.50 framing_target=root.1.0.key framing_kind=SHORTER";
        assert!(config.status().contains(status));
        for mode in ["MUTATE", "OVERFLOW", "OFF", "RESET"] {
            config
                .apply_debug_command(&strings(["DEBUG", "EVIL", "MODE", mode]))
                .unwrap();
            assert!(config.status().contains(status));
        }
        let before = config.status();
        for args in [
            vec![],
            vec!["unknown"],
            vec!["OFF", "extra"],
            vec!["AUTO", "PROBABILITY", "50"],
            vec!["LENGTH", "KIND"],
            vec!["LENGTH", "KIND", "bad"],
            vec!["LENGTH", "unexpected", "0"],
            vec!["LENGTH", "PROBABILITY", "NaN"],
            vec!["LENGTH", "PROBABILITY", "inf"],
            vec!["LENGTH", "PROBABILITY", "-1"],
            vec!["LENGTH", "PROBABILITY", "101"],
            vec!["LENGTH", "PROBABILITY", "10", "PROBABILITY", "20"],
            vec!["LENGTH", "TARGET", "ANY", "TARGET", "root"],
            vec!["LENGTH", "KIND", "LONGER", "KIND", "SHORTER"],
            vec!["LENGTH", "TARGET", "0"],
            vec!["LENGTH", "TARGET", "root."],
            vec!["LENGTH", "TARGET", "root.-1"],
            vec!["LENGTH", "TARGET", "root.key"],
            vec!["LENGTH", "TARGET", "root.0.key.value"],
            vec!["LENGTH", "TARGET", "root.99999999999999999999999999"],
        ] {
            let argv = ["DEBUG", "EVIL", "FRAMING"]
                .into_iter()
                .chain(args)
                .map(str::to_owned)
                .collect::<Vec<_>>();
            assert!(config.apply_debug_command(&argv).is_err(), "{argv:?}");
            assert_eq!(config.status(), before, "{argv:?}");
        }
        // A fresh LENGTH selection resets its options, not value probability.
        config
            .apply_debug_command(&strings([
                "DEBUG", "EVIL", "FRAMING", "LENGTH",
            ]))
            .unwrap();
        assert_eq!(config.probability, 0.0);
        assert_eq!(
            config.framing.status(),
            "framing=LENGTH framing_probability=100.00 framing_target=ANY framing_kind=RANDOM"
        );
        for setting in ["OFF", "AUTO"] {
            config
                .apply_debug_command(&strings([
                    "DEBUG", "EVIL", "FRAMING", setting,
                ]))
                .unwrap();
            assert_eq!(config.framing.status(), format!("framing={setting}"));
        }
    }

    #[test]
    fn generator_settings_survive_reset_and_rejected_updates() {
        let mut config = EvilConfig::default();
        config
            .apply_debug_command(&strings([
                "DEBUG",
                "EVIL",
                "GENERATOR",
                "PROTOCOL",
                "RESP3",
                "CORPUS",
                "RANDOM",
                "VIOLATIONS",
                "ON",
            ]))
            .unwrap();
        let status = "generator_protocol=RESP3 generator_corpus=RANDOM generator_violations=ON";
        for mode in ["RANDOM", "MUTATE", "OVERFLOW", "OFF", "RESET"] {
            config
                .apply_debug_command(&strings(["DEBUG", "EVIL", "MODE", mode]))
                .unwrap();
            assert!(config.status().ends_with(status));
        }
        let before = config.status();
        for args in [
            vec![],
            vec!["PROTOCOL"],
            vec!["PROTOCOL", "RESP2", "CORPUS", "bad"],
            vec!["CORPUS", "BOUNDARY", "CORPUS", "RANDOM"],
            vec!["VIOLATIONS", "OFF", "extra"],
        ] {
            let argv = ["DEBUG", "EVIL", "GENERATOR"]
                .into_iter()
                .chain(args)
                .map(str::to_owned)
                .collect::<Vec<_>>();
            assert!(config.apply_debug_command(&argv).is_err());
            assert_eq!(config.status(), before);
        }
        config
            .apply_debug_command(&strings([
                "DEBUG",
                "EVIL",
                "GENERATOR",
                "VIOLATIONS",
                "OFF",
            ]))
            .unwrap();
        assert!(config.status().ends_with("generator_protocol=RESP3 generator_corpus=RANDOM generator_violations=OFF"));
    }

    #[test]
    fn seed_and_status_accept_exact_arguments() {
        let mut config = EvilConfig::default();
        config
            .apply_debug_command(&strings(["DEBUG", "EVIL", "SEED", "7"]))
            .unwrap();
        assert_eq!(config.seed, 7);
        let result = config
            .apply_debug_command(&strings(["DEBUG", "EVIL", "STATUS"]))
            .unwrap();
        assert_eq!(
            result.frame,
            Frame::BulkString(Some(config.status().into_bytes()))
        );
    }

    #[test]
    fn debug_canonicalize_sets_mode() {
        let mut config = EvilConfig::default();

        assert_eq!(config.canonicalization, CanonicalizationMode::Unordered);

        config
            .apply_debug_command(&strings([
                "DEBUG",
                "EVIL",
                "CANONICALIZE",
                "ALL",
            ]))
            .unwrap();

        assert_eq!(config.canonicalization, CanonicalizationMode::All);
        assert!(config.status().contains("canonicalize=ALL"));
    }

    #[test]
    fn debug_canonicalize_rejects_unknown_mode() {
        let mut config = EvilConfig::default();

        let error = config
            .apply_debug_command(&strings([
                "DEBUG",
                "EVIL",
                "CANONICALIZE",
                "SOMETIMES",
            ]))
            .unwrap_err();

        assert!(error.to_string().contains("unknown canonicalization mode"));
    }

    #[test]
    fn debug_topology_parses_probability() {
        let mut config = EvilConfig::default();

        config
            .apply_debug_command(&strings([
                "DEBUG", "EVIL", "TOPOLOGY", "12.5",
            ]))
            .unwrap();

        assert_eq!(config.topology_probability, 12.5);
        assert!(config.status().contains("topology_probability=12.50"));
    }

    #[test]
    fn debug_topology_rejects_out_of_range_probability() {
        let mut config = EvilConfig::default();

        let error = config
            .apply_debug_command(&strings(["DEBUG", "EVIL", "TOPOLOGY", "101"]))
            .unwrap_err();

        assert!(error.to_string().contains("outside 0.00-100.00"));
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
        let first = mutate_reply(&config, 9, "command", "upstream", &frame);
        let second = mutate_reply(&config, 9, "command", "upstream", &frame);

        assert_eq!(first.bytes, second.bytes);
        assert!(!first.mutations.is_empty());
    }

    #[test]
    fn one_mutation_selects_original_children_with_exact_seeded_output() {
        let frame =
            parse_frame(b"*2\r\n#t\r\n%1\r\n#t\r\n~1\r\n#t\r\n").unwrap();
        // Seeds 0, 1, and 2 select the array child, nested set child,
        // and map key respectively for this command/reply hash tuple.
        for (seed, path, expected) in [
            (0, "root.0", b"*2\r\n#f\r\n%1\r\n#t\r\n~1\r\n#t\r\n"),
            (
                1,
                "root.1.0.value.0",
                b"*2\r\n#t\r\n%1\r\n#t\r\n~1\r\n#f\r\n",
            ),
            (2, "root.1.0.key", b"*2\r\n#t\r\n%1\r\n#f\r\n~1\r\n#t\r\n"),
        ] {
            let config = EvilConfig {
                seed,
                mode: EvilMode::Mutate,
                probability: 100.0,
                mutation_count: MutationCount::One,
                ..EvilConfig::default()
            };
            let result =
                mutate_reply(&config, 9, "command", "upstream", &frame);
            assert_eq!(result.bytes, expected);
            assert_eq!(result.mutations.len(), 1);
            assert_eq!(result.mutations[0].path, path);
            assert_eq!(result.mutations[0].kind, MutationKind::RandomValue);
        }
    }

    #[test]
    fn replacement_subtrees_are_not_mutated_again() {
        let frame =
            parse_frame(b"*2\r\n#t\r\n%1\r\n#t\r\n~1\r\n#t\r\n").unwrap();
        // Seed 1 generates an array containing nested arrays. MANY may
        // corrupt its root length but must not mutate the generated children.
        let config = EvilConfig {
            seed: 1,
            mode: EvilMode::Mutate,
            probability: 100.0,
            strategy: MutationStrategy::Replace,
            ..EvilConfig::default()
        };
        let result = mutate_reply(&config, 9, "command", "upstream", &frame);
        assert_eq!(
            result.bytes,
            b"*5\r\n*4\r\n*-1\r\n:9223372036854775807\r\n+-1\r\n*-1\r\n*1\r\n:2147483648\r\n*-1\r\n-ERR -1\r\n"
        );
        assert_eq!(
            result
                .mutations
                .iter()
                .map(|m| (m.path.as_str(), m.kind))
                .collect::<Vec<_>>(),
            [
                ("root", MutationKind::RandomFrame),
                ("root", MutationKind::WrongLength),
            ]
        );

        // Seed 107 with ONE replaces the root with a complete four-item array.
        let config = EvilConfig {
            seed: 107,
            mutation_count: MutationCount::One,
            ..config
        };
        let result = mutate_reply(&config, 9, "command", "upstream", &frame);
        assert_eq!(result.bytes, b"*4\r\n$-1\r\n$-1\r\n-ERR -1\r\n*-1\r\n");
        assert_eq!(result.mutations.len(), 1);
        assert_eq!(result.mutations[0].path, "root");
        assert_eq!(result.mutations[0].kind, MutationKind::RandomFrame);
    }

    #[test]
    fn unordered_canonicalization_sorts_hgetall_pairs_by_field() {
        let frame = parse_frame(
            b"*4\r\n$2\r\nk2\r\n$2\r\nv2\r\n$2\r\nk1\r\n$2\r\nv1\r\n",
        )
        .unwrap();

        let canonical = canonicalize_reply(
            CanonicalizationMode::Unordered,
            Some("HGETALL"),
            &frame,
        );

        assert_eq!(
            canonical.encode(),
            b"*4\r\n$2\r\nk1\r\n$2\r\nv1\r\n$2\r\nk2\r\n$2\r\nv2\r\n"
        );
    }

    #[test]
    fn unordered_canonicalization_sorts_smembers_items() {
        let frame =
            parse_frame(b"*3\r\n$1\r\nc\r\n$1\r\na\r\n$1\r\nb\r\n").unwrap();

        let canonical = canonicalize_reply(
            CanonicalizationMode::Unordered,
            Some("SMEMBERS"),
            &frame,
        );

        assert_eq!(
            canonical.encode(),
            b"*3\r\n$1\r\na\r\n$1\r\nb\r\n$1\r\nc\r\n"
        );
    }

    #[test]
    fn unordered_canonicalization_leaves_ordered_array_commands_alone() {
        let frame =
            parse_frame(b"*3\r\n$1\r\nc\r\n$1\r\na\r\n$1\r\nb\r\n").unwrap();

        let canonical = canonicalize_reply(
            CanonicalizationMode::Unordered,
            Some("LRANGE"),
            &frame,
        );

        assert_eq!(canonical, frame);
    }

    #[test]
    fn unordered_canonicalization_leaves_nested_ordered_arrays_alone() {
        let frame = parse_frame(
            b"*2\r\n*2\r\n$1\r\nb\r\n$1\r\na\r\n*2\r\n$1\r\nd\r\n$1\r\nc\r\n",
        )
        .unwrap();

        let canonical = canonicalize_reply(
            CanonicalizationMode::Unordered,
            Some("LRANGE"),
            &frame,
        );

        assert_eq!(canonical, frame);
    }

    #[test]
    fn all_canonicalization_sorts_nested_containers_recursively() {
        let frame = parse_frame(
            b"*2\r\n*2\r\n$1\r\nb\r\n$1\r\na\r\n*2\r\n$1\r\nd\r\n$1\r\nc\r\n",
        )
        .unwrap();

        let canonical = canonicalize_reply(
            CanonicalizationMode::All,
            Some("LRANGE"),
            &frame,
        );

        assert_eq!(
            canonical.encode(),
            b"*2\r\n*2\r\n$1\r\na\r\n$1\r\nb\r\n*2\r\n$1\r\nc\r\n$1\r\nd\r\n"
        );
    }

    #[test]
    fn canonicalized_unordered_replies_drive_same_mutation_output() {
        let config = EvilConfig {
            seed: 1234,
            mode: EvilMode::Mutate,
            probability: 100.0,
            ..EvilConfig::default()
        };
        let first = canonicalize_reply(
            config.canonicalization,
            Some("SMEMBERS"),
            &parse_frame(b"*3\r\n$1\r\na\r\n$1\r\nb\r\n$1\r\nc\r\n").unwrap(),
        );
        let second = canonicalize_reply(
            config.canonicalization,
            Some("SMEMBERS"),
            &parse_frame(b"*3\r\n$1\r\nc\r\n$1\r\na\r\n$1\r\nb\r\n").unwrap(),
        );
        let first_hash = deterministic_hash(&first.encode());
        let second_hash = deterministic_hash(&second.encode());

        assert_eq!(first_hash, second_hash);
        assert_eq!(
            mutate_reply(&config, 9, "command", &first_hash, &first).bytes,
            mutate_reply(&config, 9, "command", &second_hash, &second).bytes
        );
    }

    #[test]
    fn random_replies_are_deterministic_for_repro_tuple() {
        let config = EvilConfig {
            seed: 1234,
            mode: EvilMode::Random,
            probability: 100.0,
            ..EvilConfig::default()
        };

        let first = random_reply(&config, 9, "command");
        let second = random_reply(&config, 9, "command");

        assert_eq!(first.bytes, second.bytes);
        assert!(!first.mutations.is_empty());
    }

    #[test]
    fn mutations_change_with_command_index() {
        let config = EvilConfig {
            seed: 1234,
            mode: EvilMode::Mutate,
            probability: 100.0,
            ..EvilConfig::default()
        };

        let frame = parse_frame(b"*2\r\n$3\r\nfoo\r\n:1\r\n").unwrap();
        let first = mutate_reply(&config, 9, "command", "upstream", &frame);
        let second = mutate_reply(&config, 10, "command", "upstream", &frame);

        assert_ne!(first.bytes, second.bytes);
    }

    fn strings<const N: usize>(items: [&str; N]) -> Vec<String> {
        items.into_iter().map(str::to_owned).collect()
    }
}
