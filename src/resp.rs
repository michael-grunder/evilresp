use std::io::{self, ErrorKind};

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};

use crate::error::{AppError, AppResult};

// Bound incoming data, including aggregate contents. Generated evil output
// deliberately does not use these limits.
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
const MAX_FRAME_DEPTH: usize = 128;

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
        self.encode_into(&mut out, &mut |_| None);
        out
    }

    /// Override one length header by pre-order frame index. Bodies and
    /// child traversal always use actual sizes, never the advertised length.
    pub(crate) fn encode_with_length(
        &self,
        target: usize,
        replacement: &str,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let mut index = 0;
        self.encode_into(&mut out, &mut |_| {
            let selected = index == target;
            index += 1;
            selected.then_some(replacement)
        });
        out
    }

    pub(crate) fn declared_length(&self) -> Option<i128> {
        match self {
            Self::BulkString(None) | Self::Array(None) => Some(-1),
            Self::BulkString(Some(bytes))
            | Self::BulkError(bytes)
            | Self::VerbatimString(bytes) => Some(bytes.len() as i128),
            Self::Array(Some(items)) | Self::Set(items) | Self::Push(items) => {
                Some(items.len() as i128)
            }
            Self::Map(items) | Self::Attribute(items) => {
                Some(items.len() as i128)
            }
            _ => None,
        }
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
                .map(|item| match item {
                    Frame::BulkString(Some(bytes)) => {
                        Some(String::from_utf8_lossy(bytes).into_owned())
                    }
                    Frame::SimpleString(value) => Some(value.clone()),
                    Frame::VerbatimString(bytes) => {
                        Some(String::from_utf8_lossy(bytes).into_owned())
                    }
                    _ => None,
                })
                // Never shift argument positions by dropping invalid items:
                // that could turn malformed input into a local DEBUG command.
                .collect::<Option<Vec<_>>>()
                .unwrap_or_default(),
            Frame::Inline(parts) => parts
                .iter()
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect(),
            _ => Vec::new(),
        }
    }

    fn encode_into<'a>(
        &self,
        out: &mut Vec<u8>,
        header: &mut impl FnMut(&Frame) -> Option<&'a str>,
    ) {
        let replacement = header(self);
        match self {
            Frame::SimpleString(value) => {
                push_line(out, b'+', value.as_bytes())
            }
            Frame::SimpleError(value) => push_line(out, b'-', value.as_bytes()),
            Frame::Integer(value) => {
                push_line(out, b':', value.to_string().as_bytes())
            }
            Frame::BulkString(Some(bytes)) => {
                push_blob(out, b'$', bytes, replacement)
            }
            Frame::BulkString(None) => {
                push_line(out, b'$', replacement.unwrap_or("-1").as_bytes())
            }
            Frame::Array(Some(items)) => {
                push_line(
                    out,
                    b'*',
                    replacement.unwrap_or(&items.len().to_string()).as_bytes(),
                );
                for item in items {
                    item.encode_into(out, header);
                }
            }
            Frame::Array(None) => {
                push_line(out, b'*', replacement.unwrap_or("-1").as_bytes())
            }
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
            Frame::BulkError(bytes) => push_blob(out, b'!', bytes, replacement),
            Frame::VerbatimString(bytes) => {
                push_blob(out, b'=', bytes, replacement)
            }
            Frame::Map(items) => {
                push_line(
                    out,
                    b'%',
                    replacement.unwrap_or(&items.len().to_string()).as_bytes(),
                );
                for (key, value) in items {
                    key.encode_into(out, header);
                    value.encode_into(out, header);
                }
            }
            Frame::Set(items) => {
                push_line(
                    out,
                    b'~',
                    replacement.unwrap_or(&items.len().to_string()).as_bytes(),
                );
                for item in items {
                    item.encode_into(out, header);
                }
            }
            Frame::Push(items) => {
                push_line(
                    out,
                    b'>',
                    replacement.unwrap_or(&items.len().to_string()).as_bytes(),
                );
                for item in items {
                    item.encode_into(out, header);
                }
            }
            Frame::Attribute(items) => {
                push_line(
                    out,
                    b'|',
                    replacement.unwrap_or(&items.len().to_string()).as_bytes(),
                );
                for (key, value) in items {
                    key.encode_into(out, header);
                    value.encode_into(out, header);
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

fn push_blob(
    out: &mut Vec<u8>,
    prefix: u8,
    bytes: &[u8],
    replacement: Option<&str>,
) {
    push_line(
        out,
        prefix,
        replacement.unwrap_or(&bytes.len().to_string()).as_bytes(),
    );
    out.extend_from_slice(bytes);
    out.extend_from_slice(b"\r\n");
}

pub fn parse_frame(bytes: &[u8]) -> AppResult<Frame> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(AppError::Resp("RESP frame exceeds 64 MiB".to_owned()));
    }
    let mut parser = Parser {
        bytes,
        position: 0,
        depth: 0,
    };
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
    let mut raw = Vec::new();
    // Each entry counts the unread children at that nesting level. Reading
    // into one buffer avoids recursive futures and repeated subtree copies.
    let mut pending = vec![1_usize];
    while let Some(remaining) = pending.last_mut() {
        if *remaining == 0 {
            pending.pop();
            continue;
        }
        *remaining -= 1;
        if pending.len() > MAX_FRAME_DEPTH {
            return Err(invalid_data("RESP nesting exceeds 128 levels"));
        }
        if raw.len() == MAX_FRAME_BYTES {
            return Err(invalid_data("RESP frame exceeds 64 MiB"));
        }
        let mut prefix = [0_u8; 1];
        reader.read_exact(&mut prefix).await?;
        raw.push(prefix[0]);
        let line = read_line_raw(reader, &mut raw).await?;

        match prefix[0] {
            b'$' | b'!' | b'=' => {
                if let Some(len) = parse_len(&line, prefix[0] == b'$')? {
                    let body_len = len.checked_add(2).ok_or_else(|| {
                        invalid_data("RESP blob length overflow")
                    })?;
                    if body_len > MAX_FRAME_BYTES - raw.len() {
                        return Err(invalid_data("RESP frame exceeds 64 MiB"));
                    }
                    // Grow only as bytes arrive, never from an advertised
                    // length alone.
                    let mut body = (&mut *reader).take(body_len as u64);
                    if body.read_to_end(&mut raw).await? != body_len {
                        return Err(io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "truncated RESP blob",
                        ));
                    }
                    if !raw.ends_with(b"\r\n") {
                        return Err(invalid_data(
                            "bulk body missing CRLF terminator",
                        ));
                    }
                }
            }
            b'*' | b'~' | b'>' | b'%' | b'|' => {
                if let Some(len) = parse_len(&line, prefix[0] == b'*')? {
                    let children = if matches!(prefix[0], b'%' | b'|') {
                        len.checked_mul(2).ok_or_else(|| {
                            invalid_data("RESP aggregate length overflow")
                        })?
                    } else {
                        len
                    };
                    // Even the shortest child needs a prefix and CRLF.
                    if children > (MAX_FRAME_BYTES - raw.len()) / 3 {
                        return Err(invalid_data("RESP frame exceeds 64 MiB"));
                    }
                    if children > 0 {
                        pending.push(children);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(raw)
}

async fn read_line_raw<R>(
    reader: &mut R,
    raw: &mut Vec<u8>,
) -> io::Result<Vec<u8>>
where
    R: AsyncBufRead + Unpin,
{
    let before = raw.len();
    let mut limited = reader.take((MAX_FRAME_BYTES - before) as u64);
    let read = limited.read_until(b'\n', raw).await?;
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

fn parse_len(line: &[u8], nullable: bool) -> io::Result<Option<usize>> {
    let value = std::str::from_utf8(line).map_err(invalid_data)?;
    let len = value.parse::<i64>().map_err(invalid_data)?;
    if nullable && len == -1 {
        return Ok(None);
    }
    usize::try_from(len).map(Some).map_err(invalid_data)
}

fn invalid_data(error: impl ToString) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, error.to_string())
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn parse_frame(&mut self) -> AppResult<Frame> {
        if self.depth == MAX_FRAME_DEPTH {
            return Err(AppError::Resp(
                "RESP nesting exceeds 128 levels".to_owned(),
            ));
        }
        self.depth += 1;
        let result = self.parse_frame_inner();
        self.depth -= 1;
        result
    }

    fn parse_frame_inner(&mut self) -> AppResult<Frame> {
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
        if len == -1 {
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
        if len == -1 {
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
        self.validate_sequence_len(len, 6)?;
        let mut items = Vec::new();
        for _ in 0..len {
            items.push((self.parse_frame()?, self.parse_frame()?));
        }
        Ok(build(items))
    }

    fn read_sequence(&mut self, len: i64) -> AppResult<Vec<Frame>> {
        self.validate_sequence_len(len, 3)?;
        let mut items = Vec::new();
        for _ in 0..len {
            items.push(self.parse_frame()?);
        }
        Ok(items)
    }

    fn validate_sequence_len(
        &self,
        len: i64,
        minimum_bytes: usize,
    ) -> AppResult<()> {
        if usize_len(len)? > (self.bytes.len() - self.position) / minimum_bytes
        {
            return Err(AppError::Resp("truncated RESP aggregate".to_owned()));
        }
        Ok(())
    }

    fn take_blob(&mut self, len: i64) -> AppResult<Vec<u8>> {
        let len = usize_len(len)?;
        let available = self.bytes.len() - self.position;
        if available < 2 || len > available - 2 {
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

    #[tokio::test]
    async fn rejects_invalid_lengths_without_allocating_advertised_sizes() {
        for bytes in [
            b"$9223372036854775807\r\n".as_slice(),
            b"*9223372036854775807\r\n",
            b"%9223372036854775807\r\n",
            b"|9223372036854775807\r\n",
            b"$-2\r\n",
            b"*-2\r\n",
            b"!-1\r\n",
            b"=-1\r\n",
            b"%-1\r\n",
            b"~-1\r\n",
            b">-1\r\n",
            b"|-1\r\n",
        ] {
            assert!(parse_frame(bytes).is_err(), "{bytes:?}");
            let error = read_raw_frame(&mut &bytes[..]).await.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidData, "{bytes:?}");
        }
    }

    #[tokio::test]
    async fn reads_fragmented_and_pipelined_frames_without_overreading() {
        let frames: &[&[u8]] = &[
            b"$-1\r\n",
            b"*-1\r\n",
            b"$0\r\n\r\n",
            b"*0\r\n",
            b"%1\r\n+k\r\n*2\r\n$3\r\na\0b\r\n#f\r\n",
            b"|1\r\n+k\r\n:1\r\n",
            b">1\r\n+message\r\n",
            b"!3\r\nERR\r\n",
            b"=7\r\ntxt:abc\r\n",
            b"PING\r\n",
        ];
        let input = frames.concat();
        let mut reader =
            tokio::io::BufReader::with_capacity(1, input.as_slice());
        for frame in frames {
            assert_eq!(read_raw_frame(&mut reader).await.unwrap(), *frame);
            assert_eq!(parse_frame(frame).unwrap().encode(), *frame);
        }
        assert_eq!(
            read_raw_frame(&mut reader).await.unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn rejects_truncated_frames_and_invalid_terminators() {
        for bytes in [
            b"+OK".as_slice(),
            b"+OK\n",
            b"PING",
            b"PING\n",
            b"$3\r\nab",
            b"$3\r\nabcxx",
            b"*1\r\n",
            b"%1\r\n+k\r\n",
        ] {
            assert!(parse_frame(bytes).is_err(), "{bytes:?}");
            assert!(
                read_raw_frame(&mut &bytes[..]).await.is_err(),
                "{bytes:?}"
            );
        }
    }

    #[tokio::test]
    async fn enforces_nesting_limit_in_reader_and_parser() {
        let mut allowed = b"*1\r\n".repeat(MAX_FRAME_DEPTH - 1);
        allowed.extend_from_slice(b"_\r\n");
        assert_eq!(parse_frame(&allowed).unwrap().encode(), allowed);
        assert_eq!(
            read_raw_frame(&mut allowed.as_slice()).await.unwrap(),
            allowed
        );

        let mut too_deep = b"*1\r\n".to_vec();
        too_deep.extend_from_slice(&allowed);
        assert!(parse_frame(&too_deep).is_err());
        assert_eq!(
            read_raw_frame(&mut too_deep.as_slice())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn malformed_command_arguments_are_not_silently_removed() {
        let frame = parse_frame(b"*3\r\n:0\r\n+DEBUG\r\n+EVIL\r\n").unwrap();
        assert!(frame.argv_lossy().is_empty());
        assert!(frame.command_name().is_none());
        let frame =
            parse_frame(b"*4\r\n+DEBUG\r\n_\r\n+EVIL\r\n+STATUS\r\n").unwrap();
        assert!(frame.argv_lossy().is_empty());
    }

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
