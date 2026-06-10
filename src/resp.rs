use std::future::Future;
use std::io::{self, ErrorKind};
use std::pin::Pin;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};

use crate::error::{AppError, AppResult};

#[derive(Clone, Debug, PartialEq)]
pub enum Frame {
    SimpleString(String),
    SimpleError(String),
    Integer(i64),
    BulkString(Option<Vec<u8>>),
    Array(Option<Vec<Frame>>),
    Null,
    Boolean(bool),
    Double(String),
    BigNumber(String),
    BulkError(Vec<u8>),
    VerbatimString(Vec<u8>),
    Map(Vec<(Frame, Frame)>),
    Set(Vec<Frame>),
    Push(Vec<Frame>),
    Attribute(Vec<(Frame, Frame)>),
    Inline(Vec<Vec<u8>>),
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    pub fn command_name(&self) -> Option<String> {
        self.argv_lossy()
            .first()
            .map(|command| command.to_ascii_uppercase())
    }

    pub fn argv_lossy(&self) -> Vec<String> {
        match self {
            Frame::Array(Some(items)) => items
                .iter()
                .filter_map(|item| match item {
                    Frame::BulkString(Some(bytes)) => {
                        Some(String::from_utf8_lossy(bytes).into_owned())
                    }
                    Frame::SimpleString(value) => Some(value.clone()),
                    Frame::VerbatimString(bytes) => {
                        Some(String::from_utf8_lossy(bytes).into_owned())
                    }
                    _ => None,
                })
                .collect(),
            Frame::Inline(parts) => parts
                .iter()
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect(),
            _ => Vec::new(),
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Frame::SimpleString(value) => {
                push_line(out, b'+', value.as_bytes())
            }
            Frame::SimpleError(value) => push_line(out, b'-', value.as_bytes()),
            Frame::Integer(value) => {
                push_line(out, b':', value.to_string().as_bytes())
            }
            Frame::BulkString(Some(bytes)) => push_blob(out, b'$', bytes),
            Frame::BulkString(None) => out.extend_from_slice(b"$-1\r\n"),
            Frame::Array(Some(items)) => {
                push_line(out, b'*', items.len().to_string().as_bytes());
                for item in items {
                    item.encode_into(out);
                }
            }
            Frame::Array(None) => out.extend_from_slice(b"*-1\r\n"),
            Frame::Null => out.extend_from_slice(b"_\r\n"),
            Frame::Boolean(value) => {
                out.extend_from_slice(if *value {
                    b"#t\r\n"
                } else {
                    b"#f\r\n"
                });
            }
            Frame::Double(value) => push_line(out, b',', value.as_bytes()),
            Frame::BigNumber(value) => push_line(out, b'(', value.as_bytes()),
            Frame::BulkError(bytes) => push_blob(out, b'!', bytes),
            Frame::VerbatimString(bytes) => push_blob(out, b'=', bytes),
            Frame::Map(items) => {
                push_line(out, b'%', items.len().to_string().as_bytes());
                for (key, value) in items {
                    key.encode_into(out);
                    value.encode_into(out);
                }
            }
            Frame::Set(items) => {
                push_line(out, b'~', items.len().to_string().as_bytes());
                for item in items {
                    item.encode_into(out);
                }
            }
            Frame::Push(items) => {
                push_line(out, b'>', items.len().to_string().as_bytes());
                for item in items {
                    item.encode_into(out);
                }
            }
            Frame::Attribute(items) => {
                push_line(out, b'|', items.len().to_string().as_bytes());
                for (key, value) in items {
                    key.encode_into(out);
                    value.encode_into(out);
                }
            }
            Frame::Inline(parts) => {
                for (index, part) in parts.iter().enumerate() {
                    if index > 0 {
                        out.push(b' ');
                    }
                    out.extend_from_slice(part);
                }
                out.extend_from_slice(b"\r\n");
            }
        }
    }
}

fn push_line(out: &mut Vec<u8>, prefix: u8, value: &[u8]) {
    out.push(prefix);
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n");
}

fn push_blob(out: &mut Vec<u8>, prefix: u8, bytes: &[u8]) {
    push_line(out, prefix, bytes.len().to_string().as_bytes());
    out.extend_from_slice(bytes);
    out.extend_from_slice(b"\r\n");
}

pub fn parse_frame(bytes: &[u8]) -> AppResult<Frame> {
    let mut parser = Parser { bytes, position: 0 };
    let frame = parser.parse_frame()?;
    if parser.position != bytes.len() {
        return Err(AppError::Resp(format!(
            "trailing bytes after RESP frame at offset {}",
            parser.position
        )));
    }
    Ok(frame)
}

pub async fn read_raw_frame<R>(reader: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncBufRead + Unpin + Send,
{
    read_raw_frame_boxed(reader).await
}

fn read_raw_frame_boxed<'a, R>(
    reader: &'a mut R,
) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + 'a>>
where
    R: AsyncBufRead + Unpin + Send + 'a,
{
    Box::pin(async move {
        let mut prefix = [0_u8; 1];
        reader.read_exact(&mut prefix).await?;

        if !is_resp_prefix(prefix[0]) {
            let mut raw = vec![prefix[0]];
            reader.read_until(b'\n', &mut raw).await?;
            return Ok(raw);
        }

        let mut raw = vec![prefix[0]];
        let line = read_line_raw(reader, &mut raw).await?;

        match prefix[0] {
            b'$' | b'!' | b'=' => {
                let len = parse_len(&line)?;
                if len >= 0 {
                    let byte_len =
                        usize::try_from(len).map_err(invalid_data)?;
                    let mut body = vec![0_u8; byte_len + 2];
                    reader.read_exact(&mut body).await?;
                    if !body.ends_with(b"\r\n") {
                        return Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "bulk body missing CRLF terminator",
                        ));
                    }
                    raw.extend_from_slice(&body);
                }
            }
            b'*' | b'~' | b'>' => {
                let len = parse_len(&line)?;
                if len >= 0 {
                    for _ in 0..len {
                        raw.extend(read_raw_frame_boxed(reader).await?);
                    }
                }
            }
            b'%' | b'|' => {
                let len = parse_len(&line)?;
                if len >= 0 {
                    for _ in 0..(len * 2) {
                        raw.extend(read_raw_frame_boxed(reader).await?);
                    }
                }
            }
            b'+' | b'-' | b':' | b'_' | b'#' | b',' | b'(' => {}
            _ => unreachable!("checked by is_resp_prefix"),
        }

        Ok(raw)
    })
}

fn is_resp_prefix(prefix: u8) -> bool {
    matches!(
        prefix,
        b'+' | b'-'
            | b':'
            | b'$'
            | b'*'
            | b'_'
            | b'#'
            | b','
            | b'('
            | b'!'
            | b'='
            | b'%'
            | b'~'
            | b'>'
            | b'|'
    )
}

async fn read_line_raw<R>(
    reader: &mut R,
    raw: &mut Vec<u8>,
) -> io::Result<Vec<u8>>
where
    R: AsyncBufRead + Unpin,
{
    let before = raw.len();
    let read = reader.read_until(b'\n', raw).await?;
    if read == 0 {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "stream ended before RESP line terminator",
        ));
    }
    let line = &raw[before..];
    if !line.ends_with(b"\r\n") {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "RESP line missing CRLF terminator",
        ));
    }
    Ok(line[..line.len() - 2].to_vec())
}

fn parse_len(line: &[u8]) -> io::Result<i64> {
    let value = std::str::from_utf8(line).map_err(invalid_data)?;
    value.parse::<i64>().map_err(invalid_data)
}

fn invalid_data(error: impl ToString) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, error.to_string())
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Parser<'a> {
    fn parse_frame(&mut self) -> AppResult<Frame> {
        let Some(prefix) = self.take_byte() else {
            return Err(AppError::Resp("empty input".to_owned()));
        };

        match prefix {
            b'+' => Ok(Frame::SimpleString(self.take_utf8_line()?)),
            b'-' => Ok(Frame::SimpleError(self.take_utf8_line()?)),
            b':' => Ok(Frame::Integer(self.take_i64_line()?)),
            b'$' => self.parse_optional_blob().map(Frame::BulkString),
            b'*' => self.parse_optional_sequence(Frame::Array),
            b'_' => {
                let line = self.take_line()?;
                if !line.is_empty() {
                    return Err(AppError::Resp(
                        "RESP null must not have data".to_owned(),
                    ));
                }
                Ok(Frame::Null)
            }
            b'#' => match self.take_line()? {
                b"t" => Ok(Frame::Boolean(true)),
                b"f" => Ok(Frame::Boolean(false)),
                _ => Err(AppError::Resp("invalid RESP boolean".to_owned())),
            },
            b',' => Ok(Frame::Double(self.take_utf8_line()?)),
            b'(' => Ok(Frame::BigNumber(self.take_utf8_line()?)),
            b'!' => self.parse_required_blob().map(Frame::BulkError),
            b'=' => self.parse_required_blob().map(Frame::VerbatimString),
            b'%' => self.parse_map_like(Frame::Map),
            b'~' => self.parse_sequence(Frame::Set),
            b'>' => self.parse_sequence(Frame::Push),
            b'|' => self.parse_map_like(Frame::Attribute),
            other => self.parse_inline(other),
        }
    }

    fn parse_inline(&mut self, first: u8) -> AppResult<Frame> {
        self.position -= 1;
        let line = self.take_line()?;
        let parts = shell_words(line);
        if parts.is_empty() {
            Ok(Frame::Inline(vec![vec![first]]))
        } else {
            Ok(Frame::Inline(parts))
        }
    }

    fn parse_optional_blob(&mut self) -> AppResult<Option<Vec<u8>>> {
        let len = self.take_i64_line()?;
        if len < 0 {
            return Ok(None);
        }
        self.take_blob(len).map(Some)
    }

    fn parse_required_blob(&mut self) -> AppResult<Vec<u8>> {
        let len = self.take_i64_line()?;
        if len < 0 {
            return Err(AppError::Resp(
                "RESP3 blob types cannot have negative length".to_owned(),
            ));
        }
        self.take_blob(len)
    }

    fn parse_optional_sequence(
        &mut self,
        build: fn(Option<Vec<Frame>>) -> Frame,
    ) -> AppResult<Frame> {
        let len = self.take_i64_line()?;
        if len < 0 {
            return Ok(build(None));
        }
        self.read_sequence(len).map(Some).map(build)
    }

    fn parse_sequence(
        &mut self,
        build: fn(Vec<Frame>) -> Frame,
    ) -> AppResult<Frame> {
        let len = self.take_i64_line()?;
        if len < 0 {
            return Err(AppError::Resp(
                "RESP3 aggregate type cannot have negative length".to_owned(),
            ));
        }
        self.read_sequence(len).map(build)
    }

    fn parse_map_like(
        &mut self,
        build: fn(Vec<(Frame, Frame)>) -> Frame,
    ) -> AppResult<Frame> {
        let len = self.take_i64_line()?;
        if len < 0 {
            return Err(AppError::Resp(
                "RESP3 map-like type cannot have negative length".to_owned(),
            ));
        }
        let mut items = Vec::with_capacity(usize_len(len)?);
        for _ in 0..len {
            items.push((self.parse_frame()?, self.parse_frame()?));
        }
        Ok(build(items))
    }

    fn read_sequence(&mut self, len: i64) -> AppResult<Vec<Frame>> {
        let mut items = Vec::with_capacity(usize_len(len)?);
        for _ in 0..len {
            items.push(self.parse_frame()?);
        }
        Ok(items)
    }

    fn take_blob(&mut self, len: i64) -> AppResult<Vec<u8>> {
        let len = usize_len(len)?;
        if self.bytes.len().saturating_sub(self.position) < len + 2 {
            return Err(AppError::Resp("truncated RESP blob".to_owned()));
        }
        let blob = self.bytes[self.position..self.position + len].to_vec();
        self.position += len;
        if self.take_byte() != Some(b'\r') || self.take_byte() != Some(b'\n') {
            return Err(AppError::Resp("RESP blob missing CRLF".to_owned()));
        }
        Ok(blob)
    }

    fn take_i64_line(&mut self) -> AppResult<i64> {
        let line = self.take_utf8_line()?;
        line.parse::<i64>().map_err(|error| {
            AppError::Resp(format!("invalid integer: {error}"))
        })
    }

    fn take_utf8_line(&mut self) -> AppResult<String> {
        let line = self.take_line()?;
        std::str::from_utf8(line)
            .map(str::to_owned)
            .map_err(|error| {
                AppError::Resp(format!("invalid UTF-8 line: {error}"))
            })
    }

    fn take_line(&mut self) -> AppResult<&'a [u8]> {
        let start = self.position;
        while self.position + 1 < self.bytes.len() {
            if self.bytes[self.position] == b'\r'
                && self.bytes[self.position + 1] == b'\n'
            {
                let line = &self.bytes[start..self.position];
                self.position += 2;
                return Ok(line);
            }
            self.position += 1;
        }
        Err(AppError::Resp("missing RESP line terminator".to_owned()))
    }

    fn take_byte(&mut self) -> Option<u8> {
        let byte = self.bytes.get(self.position).copied()?;
        self.position += 1;
        Some(byte)
    }
}

fn usize_len(len: i64) -> AppResult<usize> {
    usize::try_from(len)
        .map_err(|_| AppError::Resp(format!("invalid length {len}")))
}

fn shell_words(line: &[u8]) -> Vec<Vec<u8>> {
    line.split(u8::is_ascii_whitespace)
        .filter(|part| !part.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_resp3_frame() {
        let bytes = b"%2\r\n+one\r\n:1\r\n+two\r\n*2\r\n$3\r\nfoo\r\n#t\r\n";
        let frame = parse_frame(bytes).unwrap();
        assert_eq!(
            frame,
            Frame::Map(vec![
                (Frame::SimpleString("one".to_owned()), Frame::Integer(1)),
                (
                    Frame::SimpleString("two".to_owned()),
                    Frame::Array(Some(vec![
                        Frame::BulkString(Some(b"foo".to_vec())),
                        Frame::Boolean(true),
                    ])),
                ),
            ])
        );
        assert_eq!(frame.encode(), bytes);
    }

    #[test]
    fn extracts_command_name_from_arrays_and_inline() {
        let array = parse_frame(b"*2\r\n$3\r\nget\r\n$3\r\nkey\r\n").unwrap();
        assert_eq!(array.command_name().as_deref(), Some("GET"));

        let inline = parse_frame(b"set key value\r\n").unwrap();
        assert_eq!(inline.command_name().as_deref(), Some("SET"));
    }
}
