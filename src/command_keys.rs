//! Key positions and routing flags from the upstream `COMMAND` reply.
//!
//! The cluster simulation needs each command's keys to pick a hash slot and
//! its `write`/`loading` flags to decide replica reads and `LOADING`
//! replies. Legacy `(first, last, step)` positions cover most commands;
//! movable-key commands, and commands missing from the table, defer to
//! `COMMAND GETKEYS` on the upstream.

use std::collections::BTreeMap;

use crate::resp::Frame;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CommandInfo {
    first: i64,
    last: i64,
    step: i64,
    pub write: bool,
    pub loading: bool,
    movable: bool,
    /// Pub/sub commands keep their real routing; the simulation does not
    /// model subscription connections.
    pub pubsub: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Keys {
    Known(Vec<Vec<u8>>),
    /// Ask the upstream with `COMMAND GETKEYS`.
    Lookup,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CommandTable {
    entries: BTreeMap<String, CommandInfo>,
}

impl CommandTable {
    /// Parse a `COMMAND` reply (RESP2 or RESP3). Malformed entries are
    /// skipped so one unexpected module command cannot disable the table.
    pub(crate) fn parse(reply: &Frame) -> Option<Self> {
        let Frame::Array(Some(items)) = reply else {
            return None;
        };
        let mut table = Self::default();
        for item in items {
            table.insert(item);
        }
        (!table.entries.is_empty()).then_some(table)
    }

    fn insert(&mut self, item: &Frame) {
        let Frame::Array(Some(parts)) = item else {
            return;
        };
        let (
            Some(name),
            Some(Frame::Integer(first)),
            Some(Frame::Integer(last)),
            Some(Frame::Integer(step)),
        ) = (
            parts.first().and_then(text),
            parts.get(3),
            parts.get(4),
            parts.get(5),
        )
        else {
            return;
        };
        let flags = parts.get(2).map(flag_list).unwrap_or_default();
        let has =
            |flag: &str| flags.iter().any(|f| f.eq_ignore_ascii_case(flag));
        self.entries.insert(
            name.to_ascii_lowercase(),
            CommandInfo {
                first: *first,
                last: *last,
                step: *step,
                write: has("write"),
                loading: has("loading"),
                movable: has("movablekeys"),
                pubsub: has("pubsub"),
            },
        );
        if let Some(Frame::Array(Some(subcommands))) = parts.get(9) {
            for subcommand in subcommands {
                self.insert(subcommand);
            }
        }
    }

    /// Subcommand entries (`object|encoding`) win over their container.
    pub(crate) fn lookup(&self, argv: &[Vec<u8>]) -> Option<&CommandInfo> {
        let name = String::from_utf8_lossy(argv.first()?).to_ascii_lowercase();
        argv.get(1)
            .and_then(|sub| {
                let sub = String::from_utf8_lossy(sub).to_ascii_lowercase();
                self.entries.get(&format!("{name}|{sub}"))
            })
            .or_else(|| self.entries.get(&name))
    }
}

impl CommandInfo {
    pub(crate) fn keys(&self, argv: &[Vec<u8>]) -> Keys {
        if self.movable {
            return Keys::Lookup;
        }
        if self.first <= 0 || self.step <= 0 {
            return Keys::Known(Vec::new());
        }
        let len = argv.len() as i64;
        let last = if self.last < 0 {
            len + self.last
        } else {
            self.last.min(len - 1)
        };
        let mut keys = Vec::new();
        let mut index = self.first;
        while index <= last && index < len {
            keys.push(argv[index as usize].clone());
            index += self.step;
        }
        Keys::Known(keys)
    }
}

/// Parse a `COMMAND GETKEYS` reply; errors (keyless or unknown commands)
/// mean there are no keys to route by.
pub(crate) fn parse_getkeys(reply: &Frame) -> Vec<Vec<u8>> {
    match reply {
        Frame::Array(Some(items)) => items
            .iter()
            .filter_map(|item| match item {
                Frame::BulkString(Some(bytes))
                | Frame::VerbatimString(bytes) => Some(bytes.clone()),
                Frame::SimpleString(value) => Some(value.as_bytes().to_vec()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn text(frame: &Frame) -> Option<String> {
    match frame {
        Frame::BulkString(Some(bytes)) | Frame::VerbatimString(bytes) => {
            Some(String::from_utf8_lossy(bytes).into_owned())
        }
        Frame::SimpleString(value) => Some(value.clone()),
        _ => None,
    }
}

fn flag_list(frame: &Frame) -> Vec<String> {
    match frame {
        Frame::Array(Some(items)) | Frame::Set(items) => {
            items.iter().filter_map(text).collect()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resp::parse_frame;

    fn argv(args: &[&str]) -> Vec<Vec<u8>> {
        args.iter().map(|arg| arg.as_bytes().to_vec()).collect()
    }

    fn entry(
        name: &str,
        flags: &[&str],
        first: i64,
        last: i64,
        step: i64,
    ) -> Frame {
        Frame::Array(Some(vec![
            Frame::BulkString(Some(name.as_bytes().to_vec())),
            Frame::Integer(-1),
            Frame::Set(
                flags
                    .iter()
                    .map(|flag| Frame::SimpleString((*flag).to_owned()))
                    .collect(),
            ),
            Frame::Integer(first),
            Frame::Integer(last),
            Frame::Integer(step),
        ]))
    }

    fn table() -> CommandTable {
        let mut object = match entry("object", &["loading"], 0, 0, 0) {
            Frame::Array(Some(parts)) => parts,
            _ => unreachable!(),
        };
        object.extend([
            Frame::Array(Some(Vec::new())),
            Frame::Array(Some(Vec::new())),
            Frame::Array(Some(Vec::new())),
            Frame::Array(Some(vec![entry(
                "object|encoding",
                &["readonly"],
                2,
                2,
                1,
            )])),
        ]);
        CommandTable::parse(&Frame::Array(Some(vec![
            entry("get", &["readonly", "fast"], 1, 1, 1),
            entry("mset", &["write", "denyoom"], 1, -1, 2),
            entry("ping", &["fast", "loading", "stale"], 0, 0, 0),
            entry("eval", &["noscript", "movablekeys"], 0, 0, 0),
            entry("ssubscribe", &["pubsub"], 1, -1, 1),
            Frame::Integer(3),
            Frame::Array(Some(object)),
        ])))
        .unwrap()
    }

    #[test]
    fn legacy_positions_flags_and_subcommands() {
        let table = table();
        let get = table.lookup(&argv(&["GET", "k"])).unwrap();
        assert!(!get.write && !get.loading);
        assert_eq!(get.keys(&argv(&["GET", "k"])), Keys::Known(argv(&["k"])));
        let mset = table.lookup(&argv(&["mset"])).unwrap();
        assert!(mset.write);
        assert_eq!(
            mset.keys(&argv(&["MSET", "a", "1", "b", "2"])),
            Keys::Known(argv(&["a", "b"]))
        );
        let ping = table.lookup(&argv(&["PING"])).unwrap();
        assert!(ping.loading);
        assert_eq!(ping.keys(&argv(&["PING"])), Keys::Known(Vec::new()));
        assert_eq!(
            table
                .lookup(&argv(&["EVAL", "s", "1", "k"]))
                .unwrap()
                .keys(&argv(&["EVAL"])),
            Keys::Lookup
        );
        assert!(table.lookup(&argv(&["SSUBSCRIBE", "c"])).unwrap().pubsub);
        let encoding =
            table.lookup(&argv(&["OBJECT", "ENCODING", "k"])).unwrap();
        assert_eq!(
            encoding.keys(&argv(&["OBJECT", "ENCODING", "k"])),
            Keys::Known(argv(&["k"]))
        );
        assert!(table.lookup(&argv(&["OBJECT", "HELP"])).unwrap().loading);
        assert!(table.lookup(&argv(&["NOPE"])).is_none());
        // Too few arguments yields no keys; the upstream reports arity.
        assert_eq!(get.keys(&argv(&["GET"])), Keys::Known(Vec::new()));
    }

    #[test]
    fn resp2_reply_and_getkeys_parse() {
        let reply = parse_frame(
            b"*1\r\n*6\r\n$3\r\nget\r\n:2\r\n*1\r\n+readonly\r\n:1\r\n:1\r\n:1\r\n",
        )
        .unwrap();
        let table = CommandTable::parse(&reply).unwrap();
        assert!(table.lookup(&argv(&["get"])).is_some());
        assert!(
            CommandTable::parse(&Frame::SimpleError("ERR".into())).is_none()
        );
        assert!(CommandTable::parse(&Frame::Array(Some(Vec::new()))).is_none());
        assert_eq!(
            parse_getkeys(
                &parse_frame(b"*2\r\n$1\r\na\r\n$1\r\nb\r\n").unwrap()
            ),
            argv(&["a", "b"])
        );
        assert!(
            parse_getkeys(&Frame::SimpleError("ERR no keys".into())).is_empty()
        );
    }
}
