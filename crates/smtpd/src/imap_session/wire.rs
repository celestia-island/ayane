//! The wire: reply lines, capabilities, status values and the octet helpers
//! the rest of the module shares.

use std::path::PathBuf;

use ayane_proto::Address;

use imap_codec::{
    encode::{Encoder, Fragment},
    imap_types::{
        auth::AuthMechanism,
        command::CommandBody,
        core::{AString, NonEmptyVec, Tag, Text},
        flag::{Flag, FlagFetch},
        response::{Capability, Code, Response, Status},
        status::{StatusDataItem, StatusDataItemName},
    },
    ResponseCodec,
};

use crate::maildir_reader::{Flags, MaildirReader, MessageId};

use super::session::{State, Transport};
use super::uidlist::UidMap;
use super::{Kind, Outcome};

/// One tagged reply line. `terminated` appends the CRLF that ends a command;
/// `STARTTLS` answers with the same line unterminated, because the handshake
/// follows it.
pub(crate) fn line(
    tag: &str,
    kind: Kind,
    code: Option<Code<'_>>,
    text: &str,
    terminated: bool,
) -> Vec<u8> {
    let Ok(tag) = Tag::try_from(tag.to_owned()) else {
        return Vec::new();
    };
    let text: Text<'_> = text
        .try_into()
        .unwrap_or_else(|_| "error".try_into().expect("a literal text"));
    let tag = Some(tag);
    let status = match kind {
        Kind::Ok => Status::Ok { tag, code, text },
        Kind::No => Status::No { tag, code, text },
        Kind::Bad => Status::Bad { tag, code, text },
    };
    let mut out = encode(&Response::Status(status));
    trim_crlf(&mut out);
    if terminated {
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// A tagged `BAD` without a session (for the helpers that have no `self`).
pub(crate) fn bad(tag: &str, text: &str) -> Outcome {
    Outcome {
        out: line(tag, Kind::Bad, None, text, true),
        ..Outcome::default()
    }
}

/// Why `body` may not run in `state`, if it may not.
pub(crate) fn state_refusal(state: State, body: &CommandBody<'_>) -> Option<&'static str> {
    use CommandBody as B;
    let proof = matches!(body, B::Login { .. } | B::Authenticate { .. } | B::StartTLS);
    if proof {
        return (state != State::NotAuthenticated)
            .then_some("command is not permitted after authentication");
    }
    let any_state = matches!(body, B::Capability | B::Noop | B::Check | B::Logout);
    (state == State::NotAuthenticated && !any_state).then_some("must authenticate first")
}

/// This connection's capabilities.
///
/// The extension list is advertised permanently (RFC 7162 §3.1 allows the
/// CONDSTORE capability without activation) and behaves by enabling command:
/// CONDSTORE wakes on the six commands RFC 7162 §3.1.2 names, QRESYNC on
/// `ENABLE QRESYNC`. Advertising either one makes the `[CLOSED]` response
/// code an unconditional duty on a change of mailbox — which is why the
/// capability list here is read by more than the CAPABILITY command.
pub(crate) fn capabilities(
    transport: Transport,
    starttls: bool,
) -> NonEmptyVec<Capability<'static>> {
    let mut caps = vec![Capability::Imap4Rev1];
    caps.extend(match (transport, starttls) {
        (Transport::Clear, true) => vec![Capability::StartTls, Capability::LoginDisabled],
        (Transport::Clear, false) => vec![Capability::LoginDisabled],
        (Transport::Tls, _) => vec![Capability::Auth(AuthMechanism::Plain)],
    });
    caps.extend([
        Capability::Move,
        Capability::LiteralPlus,
        Capability::Enable,
    ]);
    for name in ["UIDPLUS", "CONDSTORE", "QRESYNC"] {
        caps.push(Capability::try_from(name).expect("an atom capability"));
    }
    NonEmptyVec::try_from(caps).expect("capabilities are never empty")
}

/// The folder's directory, in [`MaildirReader`]'s spelling.
pub(crate) fn reader_dir(reader: &MaildirReader, mailbox: &Address, folder: &str) -> PathBuf {
    reader
        .folder_dir(mailbox, folder, false)
        .unwrap_or_default()
}

/// A `u32` as the non-zero number the protocol wants (0 becomes 1).
pub(crate) fn non_zero(value: u32) -> std::num::NonZeroU32 {
    std::num::NonZeroU32::new(value).unwrap_or(std::num::NonZeroU32::MIN)
}

/// Drop a trailing CRLF the encoder appended.
pub(crate) fn trim_crlf(bytes: &mut Vec<u8>) {
    if bytes.ends_with(b"\r\n") {
        bytes.truncate(bytes.len() - 2);
    }
}

/// A `StatusDataItem` for one requested name, or `None` when this server does
/// not answer it.
pub(crate) fn status_value(
    item: &StatusDataItemName,
    map: &UidMap,
    messages: &[(u32, String, bool)],
) -> Option<StatusDataItem> {
    Some(match item {
        StatusDataItemName::Messages => StatusDataItem::Messages(messages.len() as u32),
        StatusDataItemName::Recent => {
            StatusDataItem::Recent(messages.iter().filter(|(_, _, in_cur)| !in_cur).count() as u32)
        }
        StatusDataItemName::UidNext => StatusDataItem::UidNext(non_zero(map.next)),
        StatusDataItemName::UidValidity => StatusDataItem::UidValidity(non_zero(map.validity)),
        StatusDataItemName::Unseen => StatusDataItem::Unseen(
            messages.iter().filter(|(_, n, _)| !flag_of(n, 'S')).count() as u32,
        ),
        _ => return None,
    })
}

/// Whether the name carries a maildir flag suffix.
fn flag_of(name: &str, flag: char) -> bool {
    MessageId::parse(name).is_ok_and(|id| id.suffix().contains(flag))
}

/// Whether the name carries the maildir `T` suffix (`\Deleted`).
pub(crate) fn is_deleted(name: &str) -> bool {
    flag_of(name, 'T')
}

/// The flags a maildir name carries, as the protocol spells them.
pub(crate) fn flags_of(name: &str) -> Vec<FlagFetch<'static>> {
    [
        ('S', Flag::Seen),
        ('F', Flag::Flagged),
        ('T', Flag::Deleted),
        ('D', Flag::Draft),
    ]
    .into_iter()
    .filter(|(suffix, _)| flag_of(name, *suffix))
    .map(|(_, flag)| FlagFetch::Flag(flag))
    .collect()
}

/// The flags a maildir name carries, as untagged `FETCH` lines spell them —
/// the system flags this layout can hold plus `\Recent` when the session
/// considers the message recent (RFC 3501 §2.3.2 / §7.4.2). The lines the
/// extension paths hand-write (`VANISHED` companions, QRESYNC initial
/// synchronization, the NOOP refresh) render their flags from here, so they
/// carry the same set the codec-rendered `flags_of` reports — a flag set,
/// where order carries no meaning (RFC 3501 §2.3.2 spells no order for the
/// response).
pub(crate) fn flags_text(name: &str, recent: bool) -> String {
    let id = MessageId::parse(name);
    let flags = id.map(|id| id.flags()).unwrap_or_default();
    let mut out: Vec<&'static str> = Vec::new();
    if flags.flagged {
        out.push("\\Flagged");
    }
    if flags.seen {
        out.push("\\Seen");
    }
    if flags.trashed {
        out.push("\\Deleted");
    }
    if flags.draft {
        out.push("\\Draft");
    }
    if recent {
        out.push("\\Recent");
    }
    out.join(" ")
}

/// `LIST` wildcards (RFC 3501 §6.3.8). The layout is flat, so `%` and `*`
/// select the same folders.
pub(crate) fn glob(pattern: &str, name: &str) -> bool {
    fn go(p: &[u8], n: &[u8]) -> bool {
        match (p.first(), n.first()) {
            (None, None) => true,
            (Some(b'*' | b'%'), _) => go(&p[1..], n) || (!n.is_empty() && go(p, &n[1..])),
            (Some(c), Some(d)) if c.eq_ignore_ascii_case(d) => go(&p[1..], &n[1..]),
            _ => false,
        }
    }
    go(pattern.as_bytes(), name.as_bytes())
}

/// The text of an `AString` as the protocol carried it.
pub(crate) fn astring_text(value: &AString<'_>) -> String {
    match value {
        AString::Atom(atom) => atom.as_ref().to_owned(),
        AString::String(string) => String::from_utf8_lossy(string.as_ref()).into_owned(),
    }
}

/// Encode one server response.
///
/// The literal contract, measured from the codec rather than assumed: a
/// [`Fragment::Line`] ends with the item list **and its announcement**
/// (`* 1 FETCH (UID 1 BODY[] {5}` + CRLF), and the [`Fragment::Literal`] that
/// follows carries the octets **only** (`hello`). So both halves are written
/// as they come, and nothing here counts, strips or re-announces anything —
/// which is the property RFC 3501 §4.3 wants, and the one a previous version
/// of this function broke by announcing the literal a second time.
pub(crate) fn encode(response: &Response<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    for fragment in ResponseCodec::default().encode(response) {
        match fragment {
            Fragment::Line { data } => out.extend_from_slice(&data),
            // A response literal is announced on the line above it; its octets
            // go out as they are. Re-announcing them here would put `{n}` and
            // its CRLF at the head of the message.
            Fragment::Literal { data, .. } => out.extend_from_slice(&data),
        }
    }
    out
}

/// The name of a command, for a `BAD` that names what it refused — including
/// the one a connection writes itself, before it has a session to ask.
#[must_use]
pub fn command_name(body: &CommandBody<'_>) -> &'static str {
    name_of(body)
}

/// The name of a command, for a `BAD` that names what it refused.
pub(crate) fn name_of(body: &CommandBody<'_>) -> &'static str {
    match body {
        CommandBody::Create { .. } => "CREATE",
        CommandBody::Delete { .. } => "DELETE",
        CommandBody::Rename { .. } => "RENAME",
        CommandBody::Subscribe { .. } | CommandBody::Unsubscribe { .. } => "SUBSCRIBE",
        CommandBody::Idle => "IDLE",
        _ => "command",
    }
}

/// Everything up to and including the blank line that ends the header.
pub(crate) fn head_of(raw: &[u8]) -> &[u8] {
    match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(at) => &raw[..at + 4],
        None => raw,
    }
}

/// Everything after it.
pub(crate) fn body_of(raw: &[u8]) -> &[u8] {
    match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(at) => &raw[at + 4..],
        None => &[],
    }
}

/// One header field's value from the message head, unfolded.
pub(crate) fn header(head: &[u8], field: &str) -> Option<String> {
    let mut value: Option<String> = None;
    for line in String::from_utf8_lossy(head).split_inclusive('\n') {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        match line.strip_prefix([' ', '\t']) {
            Some(rest) => {
                if let Some(value) = value.as_mut() {
                    value.push(' ');
                    value.push_str(rest.trim());
                }
            }
            None => {
                if let Some((name, rest)) = line.split_once(':') {
                    if name.trim().eq_ignore_ascii_case(field) {
                        value = Some(rest.trim().to_owned());
                    }
                }
            }
        }
    }
    value
}

/// Whether a header field's value contains `needle` (ASCII case-insensitive).
pub(crate) fn header_contains(raw: &[u8], field: &str, needle: &[u8]) -> bool {
    header(raw, field).is_some_and(|text| contains(text.as_bytes(), needle))
}

/// ASCII case-insensitive substring test over bytes.
pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    let (haystack, needle) = (haystack.to_ascii_lowercase(), needle.to_ascii_lowercase());
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Whether a keyword names a flag this mailbox can hold.
pub(crate) fn keyword(name: &str, flags: Flags) -> bool {
    match name.trim_start_matches('\\').to_ascii_lowercase().as_str() {
        "seen" => flags.seen,
        "flagged" => flags.flagged,
        "deleted" => flags.trashed,
        "draft" => flags.draft,
        _ => false,
    }
}

/// The system flags this mailbox reports, in RFC 3501 §2.3.2's order.
pub(crate) fn system_flags() -> Vec<Flag<'static>> {
    vec![
        Flag::Answered,
        Flag::Flagged,
        Flag::Deleted,
        Flag::Seen,
        Flag::Draft,
    ]
}
