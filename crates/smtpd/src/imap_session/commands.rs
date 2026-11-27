//! The command dispatcher: one command in, the session's new state and the
//! bytes to write out.
//!
//! Every arm here answers through [`line`] or the session's own helpers, so a
//! reply is spelled the same whether it came from this table, from the
//! connection half (`ImapSession::refuse_no` and friends), or from a status
//! line.

use imap_codec::imap_types::{
    command::{Command as Wire, CommandBody},
    response::{Data, Status},
};

use crate::authn::decode_plain;

use super::session::{ImapSession, State};
use super::wire::{astring_text, capabilities, line, name_of, state_refusal};
use super::{Kind, Outcome};

impl ImapSession<'_> {
    /// Handle one parsed command and answer with what to write.
    pub async fn handle(&mut self, command: &Wire<'_>) -> Outcome {
        let tag = command.tag.as_ref().to_owned();
        if self.state == State::Logout {
            return self.bad(&tag, "no commands after LOGOUT");
        }
        if let Some(refusal) = state_refusal(self.state, &command.body) {
            return self.bad(&tag, refusal);
        }
        use CommandBody as B;
        match &command.body {
            B::Capability => self.reply(
                &tag,
                "CAPABILITY",
                Data::Capability(capabilities(self.transport, self.starttls)),
            ),
            B::Noop | B::Check => self.refresh(&tag),
            B::Logout => {
                let mut out = self.contained(&Status::bye(None, "Logging out").expect("bye"));
                out.extend(self.ok(&tag, "LOGOUT completed"));
                self.state = State::Logout;
                Outcome {
                    out,
                    close: true,
                    ..Outcome::default()
                }
            }
            // The line carries no CRLF: the handshake, not more text, follows.
            B::StartTLS => Outcome {
                start_tls: Some(line(
                    &tag,
                    Kind::Ok,
                    None,
                    "Begin TLS negotiation now",
                    false,
                )),
                ..Outcome::default()
            },
            B::Login { username, password } => {
                self.authenticate(
                    &tag,
                    &astring_text(username),
                    &astring_text(password.declassify()),
                )
                .await
            }
            B::Authenticate {
                initial_response, ..
            } => match initial_response {
                None => self.no(&tag, "SASL initial response required"),
                Some(initial) => match decode_plain(&String::from_utf8_lossy(initial.declassify()))
                {
                    Ok((user, pass)) => self.authenticate(&tag, &user, &pass).await,
                    Err(_) => self.no(&tag, "[AUTHENTICATIONFAILED] malformed PLAIN response"),
                },
            },
            B::List {
                mailbox_wildcard, ..
            } => self.list(&tag, mailbox_wildcard),
            B::Lsub { .. } => Outcome {
                out: self.ok(&tag, "LSUB completed"),
                ..Outcome::default()
            },
            B::Status {
                mailbox,
                item_names,
            } => self.status(&tag, mailbox, item_names),
            B::Select { mailbox } => self.select(&tag, mailbox, false),
            B::Examine { mailbox } => self.select(&tag, mailbox, true),
            B::Unselect => {
                self.selected = None;
                self.state = State::Authenticated;
                Outcome {
                    out: self.ok(&tag, "UNSELECT completed"),
                    ..Outcome::default()
                }
            }
            B::Close => self.close(&tag),
            B::Expunge => self.expunge(&tag),
            B::Append {
                mailbox,
                flags,
                message,
                ..
            } => self.append(&tag, mailbox, flags, message.data()),
            B::Fetch {
                sequence_set,
                macro_or_item_names,
                uid,
            } => self.fetch(&tag, sequence_set, macro_or_item_names, *uid),
            B::Store {
                sequence_set,
                kind,
                response,
                flags,
                uid,
            } => self.store(&tag, sequence_set, *kind, *response, flags, *uid),
            B::Search { criteria, uid, .. } => self.search(&tag, criteria, *uid),
            B::Copy {
                sequence_set,
                mailbox,
                uid,
            } => self.copy(&tag, sequence_set, mailbox, *uid, false),
            B::Move {
                sequence_set,
                mailbox,
                uid,
            } => self.copy(&tag, sequence_set, mailbox, *uid, true),
            other => self.bad(&tag, &format!("{} is not implemented here", name_of(other))),
        }
    }
}
