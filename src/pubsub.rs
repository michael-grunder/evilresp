//! Recognize subscription acknowledgements and RESP2 unsolicited messages.
//! Bookkeeping always uses original upstream frames, never mutated output.

use std::collections::BTreeSet;

use crate::resp::{Frame, parse_frame};

#[derive(Default)]
pub(crate) struct Subscriptions {
    channels: [BTreeSet<Vec<u8>>; 3],
    resp3: bool,
}

pub(crate) struct PendingSubscription {
    kind: String,
    remaining: usize,
}

fn subscription_kind(kind: &str) -> Option<(usize, bool)> {
    Some(match kind {
        "subscribe" => (0, true),
        "unsubscribe" => (0, false),
        "psubscribe" => (1, true),
        "punsubscribe" => (1, false),
        "ssubscribe" => (2, true),
        "sunsubscribe" => (2, false),
        _ => return None,
    })
}

pub(crate) fn string(frame: &Frame) -> Option<&[u8]> {
    match frame {
        Frame::BulkString(Some(bytes)) => Some(bytes),
        Frame::SimpleString(value) => Some(value.as_bytes()),
        _ => None,
    }
}

impl Subscriptions {
    pub(crate) fn pending(
        &self,
        argv: &[String],
    ) -> Option<PendingSubscription> {
        let kind = argv.first()?.to_ascii_lowercase();
        let (index, subscribe) = subscription_kind(&kind)?;
        if subscribe && argv.len() < 2 {
            return None;
        }
        let remaining = if argv.len() > 1 {
            argv.len() - 1
        } else {
            self.channels[index].len().max(1)
        };
        Some(PendingSubscription { kind, remaining })
    }

    pub(crate) fn is_event(
        &self,
        bytes: &[u8],
        pending: Option<&PendingSubscription>,
    ) -> bool {
        if bytes.first() == Some(&b'>') {
            return true;
        }
        if self.resp3 {
            return false;
        }
        let Ok(Frame::Array(Some(items))) = parse_frame(bytes) else {
            return false;
        };
        let Some(kind) = items.first().and_then(string) else {
            return false;
        };
        let active = self.channels.iter().any(|set| !set.is_empty());
        match kind {
            b"message" | b"smessage" => active && items.len() == 3,
            b"pmessage" => active && items.len() == 4,
            _ => {
                (active || pending.is_some())
                    && acknowledgement(&items).is_some()
            }
        }
    }

    /// Returns true only when the pending subscription command has completed.
    pub(crate) fn observe(
        &mut self,
        bytes: &[u8],
        pending: Option<&mut PendingSubscription>,
    ) -> bool {
        if bytes.first() == Some(&b'>') {
            self.resp3 = true;
        }
        let Ok(Frame::Push(items) | Frame::Array(Some(items))) =
            parse_frame(bytes)
        else {
            return false;
        };
        let Some((kind, index, subscribe)) = acknowledgement(&items) else {
            return false;
        };
        if let Some(channel) = string(&items[1]) {
            if subscribe {
                self.channels[index].insert(channel.to_vec());
            } else {
                self.channels[index].remove(channel);
            }
        }
        if let Some(pending) = pending
            && pending.kind == kind
        {
            pending.remaining -= 1;
            return pending.remaining == 0;
        }
        false
    }

    pub(crate) fn observe_reply(&mut self, argv: &[String], bytes: &[u8]) {
        match argv
            .first()
            .map(|name| name.to_ascii_uppercase())
            .as_deref()
        {
            Some("HELLO") if matches!(bytes.first(), Some(b'%' | b'*')) => {
                self.resp3 = bytes.first() == Some(&b'%');
            }
            Some("RESET") if bytes == b"+RESET\r\n" => *self = Self::default(),
            _ => {}
        }
    }
}

fn acknowledgement(items: &[Frame]) -> Option<(&str, usize, bool)> {
    if items.len() != 3 || !matches!(items[2], Frame::Integer(n) if n >= 0) {
        return None;
    }
    let kind = std::str::from_utf8(string(&items[0])?).ok()?;
    let (index, subscribe) = subscription_kind(kind)?;
    if string(&items[1]).is_none()
        && !matches!(items[1], Frame::Null | Frame::BulkString(None))
    {
        return None;
    }
    Some((kind, index, subscribe))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ack(
        kind: &str,
        channel: Option<&[u8]>,
        count: i64,
        resp3: bool,
    ) -> Vec<u8> {
        let items = vec![
            Frame::BulkString(Some(kind.as_bytes().to_vec())),
            Frame::BulkString(channel.map(Vec::from)),
            Frame::Integer(count),
        ];
        if resp3 {
            Frame::Push(items)
        } else {
            Frame::Array(Some(items))
        }
        .encode()
    }

    #[test]
    fn counts_each_ack_and_unsubscribes_distinct_binary_names_by_family() {
        for resp3 in [false, true] {
            let mut state = Subscriptions::default();
            for (subscribe, unsubscribe) in [
                ("SUBSCRIBE", "UNSUBSCRIBE"),
                ("PSUBSCRIBE", "PUNSUBSCRIBE"),
                ("SSUBSCRIBE", "SUNSUBSCRIBE"),
            ] {
                let mut pending = state
                    .pending(&[subscribe, "a", "a", "b"].map(str::to_owned))
                    .unwrap();
                for (i, channel) in
                    [b"a".as_slice(), b"a", b"\xff"].iter().enumerate()
                {
                    let bytes = ack(
                        &subscribe.to_ascii_lowercase(),
                        Some(channel),
                        2,
                        resp3,
                    );
                    assert!(state.is_event(&bytes, Some(&pending)));
                    assert_eq!(
                        state.observe(&bytes, Some(&mut pending)),
                        i == 2
                    );
                }
                let mut pending =
                    state.pending(&[unsubscribe.to_owned()]).unwrap();
                for (i, channel) in
                    [b"a".as_slice(), b"\xff"].iter().enumerate()
                {
                    let bytes = ack(
                        &unsubscribe.to_ascii_lowercase(),
                        Some(channel),
                        0,
                        resp3,
                    );
                    assert_eq!(
                        state.observe(&bytes, Some(&mut pending)),
                        i == 1
                    );
                }
                let mut pending =
                    state.pending(&[unsubscribe.to_owned()]).unwrap();
                assert!(state.observe(
                    &ack(&unsubscribe.to_ascii_lowercase(), None, 0, resp3),
                    Some(&mut pending)
                ));
            }
        }
    }

    #[test]
    fn arrays_are_events_only_in_resp2_subscription_context() {
        let mut state = Subscriptions::default();
        let message = b"*3\r\n$7\r\nmessage\r\n$1\r\nx\r\n$1\r\ny\r\n";
        assert!(!state.is_event(message, None));
        state.observe(&ack("subscribe", Some(b"x"), 1, false), None);
        assert!(state.is_event(message, None));
        state.observe_reply(&["HELLO", "3"].map(str::to_owned), b"%0\r\n");
        assert!(!state.is_event(message, None));
        state.observe_reply(&["HELLO", "2"].map(str::to_owned), b"-ERR no\r\n");
        assert!(!state.is_event(message, None));
        state.observe_reply(&["HELLO", "2"].map(str::to_owned), b"*0\r\n");
        assert!(state.is_event(message, None));
        state.observe_reply(&["RESET".to_owned()], b"+RESET\r\n");
        assert!(!state.is_event(message, None));
        assert!(state.is_event(b">1\r\n+unknown\r\n", None));
        assert!(!state.is_event(b"*3\r\n+subscribe\r\n+x\r\n+bad\r\n", None));
    }
}
