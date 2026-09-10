//! Track accepted transaction commands so EXEC replies retain their matching
//! command names during canonicalization, including after rejected commands.

#[derive(Default)]
pub(crate) struct TransactionCommands {
    queued: Option<Vec<String>>,
}

impl TransactionCommands {
    /// Observe the unmodified upstream reply. Return the completed command
    /// list only when the upstream actually ends the transaction.
    pub(crate) fn observe(
        &mut self,
        argv: &[String],
        reply: &[u8],
    ) -> Option<Vec<String>> {
        let command = argv.first()?.to_ascii_uppercase();
        match command.as_str() {
            "MULTI" if reply == b"+OK\r\n" => {
                self.queued = Some(Vec::new());
            }
            "DISCARD" if reply == b"+OK\r\n" => self.queued = None,
            "EXEC"
                if matches!(reply.first(), Some(b'*' | b'_'))
                    || reply.starts_with(b"-EXECABORT ") =>
            {
                return self.queued.take();
            }
            _ if reply == b"+QUEUED\r\n" => {
                if let Some(commands) = &mut self.queued {
                    commands.push(command);
                }
            }
            _ => {}
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evil::{CanonicalizationMode, canonicalize_transaction_reply};
    use crate::resp::parse_frame;

    fn observe(
        transaction: &mut TransactionCommands,
        command: &str,
        reply: &[u8],
    ) -> Option<Vec<String>> {
        transaction.observe(&[command.to_owned()], reply)
    }

    #[test]
    fn rejected_commands_do_not_shift_exec_canonicalization() {
        let mut transaction = TransactionCommands::default();
        observe(&mut transaction, "MULTI", b"+OK\r\n");
        observe(
            &mut transaction,
            "MULTI",
            b"-ERR MULTI calls can not be nested\r\n",
        );
        observe(&mut transaction, "SMEMBERS", b"+QUEUED\r\n");
        let reply = b"*1\r\n*2\r\n+b\r\n+a\r\n";
        let commands = observe(&mut transaction, "EXEC", reply).unwrap();
        assert_eq!(commands, ["SMEMBERS"]);
        assert_eq!(
            canonicalize_transaction_reply(
                CanonicalizationMode::Unordered,
                &commands,
                &parse_frame(reply).unwrap(),
            )
            .encode(),
            b"*1\r\n*2\r\n+a\r\n+b\r\n"
        );
        assert!(transaction.queued.is_none());
    }

    #[test]
    fn rejected_commands_preserve_the_queue_until_upstream_aborts() {
        let mut transaction = TransactionCommands::default();
        observe(&mut transaction, "MULTI", b"+OK\r\n");
        observe(&mut transaction, "GET", b"+QUEUED\r\n");
        for command in ["GET", "EXEC", "DISCARD"] {
            observe(
                &mut transaction,
                command,
                b"-ERR wrong number of arguments\r\n",
            );
            assert_eq!(
                transaction.queued.as_deref(),
                Some(["GET".to_owned()].as_slice())
            );
        }
        observe(
            &mut transaction,
            "EXEC",
            b"-EXECABORT Transaction discarded\r\n",
        );
        assert!(transaction.queued.is_none());
    }

    #[test]
    fn failed_multi_does_not_start_tracking() {
        let mut transaction = TransactionCommands::default();
        observe(
            &mut transaction,
            "MULTI",
            b"-ERR wrong number of arguments\r\n",
        );
        observe(&mut transaction, "GET", b"+QUEUED\r\n");
        assert!(transaction.queued.is_none());
    }

    #[test]
    fn completed_discarded_and_aborted_transactions_clear_tracking() {
        for (command, reply) in [
            ("EXEC", b"*0\r\n".as_slice()),
            ("EXEC", b"*-1\r\n"),
            ("EXEC", b"_\r\n"),
            ("EXEC", b"-EXECABORT Transaction discarded\r\n"),
            ("DISCARD", b"+OK\r\n"),
        ] {
            let mut transaction = TransactionCommands::default();
            observe(&mut transaction, "MULTI", b"+OK\r\n");
            observe(&mut transaction, "GET", b"+QUEUED\r\n");
            observe(&mut transaction, command, reply);
            assert!(transaction.queued.is_none());
            observe(&mut transaction, "MULTI", b"+OK\r\n");
            assert_eq!(
                observe(&mut transaction, "EXEC", b"*0\r\n"),
                Some(Vec::new())
            );
        }
    }
}
