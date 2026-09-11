use std::fmt;
use std::str::FromStr;

use tlsh::prelude::*;

use crate::error::{AppError, AppResult};

#[derive(Debug)]
pub struct ProtocolFingerprints {
    input: ProtocolFingerprint,
    output: ProtocolFingerprint,
}

impl ProtocolFingerprints {
    pub fn new() -> Self {
        Self {
            input: ProtocolFingerprint::new(),
            output: ProtocolFingerprint::new(),
        }
    }

    pub fn update(&mut self, direction: ProtocolDirection, bytes: &[u8]) {
        self.for_direction_mut(direction).update(bytes);
    }

    pub fn get(
        &self,
        direction: ProtocolDirection,
        algorithm: ProtocolHash,
    ) -> String {
        self.for_direction(direction).get(algorithm)
    }

    pub fn reset(&mut self) {
        self.input.reset();
        self.output.reset();
    }

    fn for_direction(
        &self,
        direction: ProtocolDirection,
    ) -> &ProtocolFingerprint {
        match direction {
            ProtocolDirection::In => &self.input,
            ProtocolDirection::Out => &self.output,
        }
    }

    fn for_direction_mut(
        &mut self,
        direction: ProtocolDirection,
    ) -> &mut ProtocolFingerprint {
        match direction {
            ProtocolDirection::In => &mut self.input,
            ProtocolDirection::Out => &mut self.output,
        }
    }
}

impl Default for ProtocolFingerprints {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolDirection {
    In,
    Out,
}

impl FromStr for ProtocolDirection {
    type Err = AppError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_uppercase().as_str() {
            "IN" => Ok(Self::In),
            "OUT" => Ok(Self::Out),
            _ => Err(AppError::ProtocolFingerprint(format!(
                "unknown protocol direction {value:?}; expected <IN|OUT>"
            ))),
        }
    }
}

impl fmt::Display for ProtocolDirection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::In => "IN",
            Self::Out => "OUT",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolHash {
    Blake3,
    Tlsh,
}

impl FromStr for ProtocolHash {
    type Err = AppError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_uppercase().as_str() {
            "BLAKE3" => Ok(Self::Blake3),
            "TLSH" => Ok(Self::Tlsh),
            _ => Err(AppError::ProtocolFingerprint(format!(
                "unknown protocol hash {value:?}; expected <BLAKE3|TLSH>"
            ))),
        }
    }
}

impl fmt::Display for ProtocolHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Blake3 => "BLAKE3",
            Self::Tlsh => "TLSH",
        })
    }
}

pub fn parse_debug_protocol(
    argv: &[String],
) -> AppResult<(ProtocolDirection, ProtocolHash)> {
    const USAGE: &str = "expected DEBUG PROTOCOL <IN|OUT> <BLAKE3|TLSH>";

    if argv.len() < 2
        || !argv[0].eq_ignore_ascii_case("DEBUG")
        || !argv[1].eq_ignore_ascii_case("PROTOCOL")
    {
        return Err(AppError::ProtocolFingerprint(USAGE.to_owned()));
    }

    let direction = argv.get(2).ok_or_else(|| {
        AppError::ProtocolFingerprint(format!(
            "{USAGE}; missing protocol direction"
        ))
    })?;
    let direction = direction.parse()?;
    let algorithm = argv.get(3).ok_or_else(|| {
        AppError::ProtocolFingerprint(format!("{USAGE}; missing protocol hash"))
    })?;
    let algorithm = algorithm.parse()?;
    if let Some(extra) = argv.get(4) {
        return Err(AppError::ProtocolFingerprint(format!(
            "{USAGE}; unexpected argument {extra:?}"
        )));
    }

    Ok((direction, algorithm))
}

#[derive(Debug)]
struct ProtocolFingerprint {
    blake3: blake3::Hasher,
    tlsh: TlshGenerator,
}

impl ProtocolFingerprint {
    fn new() -> Self {
        Self {
            blake3: blake3::Hasher::new(),
            tlsh: TlshGenerator::new(),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.blake3.update(bytes);
        self.tlsh.update(bytes);
    }

    fn get(&self, algorithm: ProtocolHash) -> String {
        match algorithm {
            ProtocolHash::Blake3 => self.blake3.finalize().to_hex().to_string(),
            ProtocolHash::Tlsh => self
                .tlsh
                .finalize()
                .map(|hash| hash.to_string())
                .unwrap_or_else(|_| "TNULL".to_owned()),
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_fingerprint_is_incremental() {
        let mut fingerprints = ProtocolFingerprints::new();
        fingerprints.update(ProtocolDirection::In, b"hello");
        fingerprints.update(ProtocolDirection::In, b" ");
        fingerprints.update(ProtocolDirection::In, b"world");

        let mut expected = blake3::Hasher::new();
        expected.update(b"hello world");

        assert_eq!(
            fingerprints.get(ProtocolDirection::In, ProtocolHash::Blake3),
            expected.finalize().to_hex().to_string()
        );
    }

    #[test]
    fn reset_zeroes_fingerprints() {
        let mut fingerprints = ProtocolFingerprints::new();
        fingerprints.update(ProtocolDirection::In, b"input");
        fingerprints.update(ProtocolDirection::Out, b"output");
        fingerprints.reset();

        assert_eq!(
            fingerprints.get(ProtocolDirection::In, ProtocolHash::Blake3),
            blake3::Hasher::new().finalize().to_hex().to_string()
        );
        assert_eq!(
            fingerprints.get(ProtocolDirection::Out, ProtocolHash::Tlsh),
            "TNULL"
        );
    }

    #[test]
    fn parses_debug_protocol_query() {
        let argv = [
            "DEBUG".to_owned(),
            "PROTOCOL".to_owned(),
            "OUT".to_owned(),
            "TLSH".to_owned(),
        ];

        assert_eq!(
            parse_debug_protocol(&argv).unwrap(),
            (ProtocolDirection::Out, ProtocolHash::Tlsh)
        );
    }
}
