//! Rendering: one message's data items as the protocol spells them, and the
//! `SEARCH` keys it can be matched against.

use imap_codec::imap_types::{
    body::{BasicFields, Body, BodyStructure, SpecificFields},
    core::{IString, Literal, NString},
    datetime::DateTime,
    envelope::{Address as EnvAddress, Envelope},
    fetch::{MessageDataItem, MessageDataItemName, Section},
    flag::FlagFetch,
    search::SearchKey,
    sequence::Strategy,
};

use crate::maildir_reader::{Flags, MessageId};

use super::session::Selected;
use super::wire::{
    body_of, contains, flags_of, head_of, header, header_contains, keyword, non_zero,
};

/// One data item as the protocol spells it, or `None` when this server does
/// not answer it.
pub(crate) fn render_item(
    item: &MessageDataItemName<'_>,
    raw: &[u8],
    id: &MessageId,
    uid: u32,
    selected: &Selected,
) -> Option<MessageDataItem<'static>> {
    Some(match item {
        MessageDataItemName::Uid => MessageDataItem::Uid(non_zero(uid)),
        MessageDataItemName::Rfc822Size => {
            MessageDataItem::Rfc822Size(u32::try_from(raw.len()).unwrap_or(u32::MAX))
        }
        MessageDataItemName::Flags => {
            let mut flags = flags_of(&id.file_name());
            if selected.is_recent(uid) {
                flags.push(FlagFetch::Recent);
            }
            MessageDataItem::Flags(flags)
        }
        MessageDataItemName::InternalDate => MessageDataItem::InternalDate(internal_date(raw)),
        MessageDataItemName::Envelope => MessageDataItem::Envelope(envelope(raw)),
        MessageDataItemName::Rfc822 => MessageDataItem::Rfc822(literal_string(raw)),
        MessageDataItemName::Rfc822Text => {
            MessageDataItem::Rfc822Text(literal_string(body_of(raw)))
        }
        MessageDataItemName::Rfc822Header => {
            MessageDataItem::Rfc822Header(literal_string(head_of(raw)))
        }
        MessageDataItemName::Body | MessageDataItemName::BodyStructure => {
            MessageDataItem::BodyStructure(text_structure(body_of(raw)))
        }
        MessageDataItemName::BodyExt {
            section, partial, ..
        } => {
            // A part number or a field subset needs a MIME walk this server
            // does not do (it stores bytes, it does not reparse them).
            let bytes = match section {
                None => raw.to_vec(),
                Some(Section::Text(None)) => body_of(raw).to_vec(),
                Some(Section::Header(None)) => head_of(raw).to_vec(),
                _ => return None,
            };
            let (bytes, origin) = match partial {
                Some((origin, length)) => {
                    let start = usize::try_from(*origin)
                        .unwrap_or(usize::MAX)
                        .min(bytes.len());
                    let end = start
                        .saturating_add(usize::try_from(length.get()).unwrap_or(usize::MAX))
                        .min(bytes.len());
                    (bytes[start..end].to_vec(), Some(*origin))
                }
                None => (bytes, None),
            };
            let section = section.as_ref().map(|section| match section {
                Section::Text(None) => Section::Text(None),
                _ => Section::Header(None),
            });
            MessageDataItem::BodyExt {
                section,
                origin,
                data: literal_string(&bytes),
            }
        }
    })
}

/// An `IString` that is always a literal, so a CRLF inside it is data.
fn literal_istring(bytes: &[u8]) -> IString<'static> {
    IString::Literal(Literal::unvalidated(bytes.to_vec()))
}

/// The same as an `NString`, which is never `NIL` here.
pub(crate) fn literal_string(bytes: &[u8]) -> NString<'static> {
    NString(Some(literal_istring(bytes)))
}

/// The one structure this server can prove: `TEXT/PLAIN` with as many lines
/// as the body has newlines.
fn text_structure(body: &[u8]) -> BodyStructure<'static> {
    BodyStructure::Single {
        body: Body {
            basic: BasicFields {
                parameter_list: Vec::new(),
                id: NString(None),
                description: NString(None),
                content_transfer_encoding: literal_istring(b"8BIT"),
                size: u32::try_from(body.len()).unwrap_or(u32::MAX),
            },
            specific: SpecificFields::Text {
                subtype: literal_istring(b"PLAIN"),
                number_of_lines: u32::try_from(body.iter().filter(|byte| **byte == b'\n').count())
                    .unwrap_or(u32::MAX),
            },
        },
        extension_data: None,
    }
}

/// The `ENVELOPE` (RFC 3501 §7.4.2) from the head's fields.
fn envelope(raw: &[u8]) -> Envelope<'static> {
    let field = |name: &str| {
        header(raw, name).map_or_else(|| NString(None), |value| literal_string(value.as_bytes()))
    };
    let from = addresses(&header(raw, "from").unwrap_or_default());
    Envelope {
        date: field("date"),
        subject: field("subject"),
        sender: from.clone(),
        from,
        reply_to: addresses(&header(raw, "reply-to").unwrap_or_default()),
        to: addresses(&header(raw, "to").unwrap_or_default()),
        cc: addresses(&header(raw, "cc").unwrap_or_default()),
        bcc: addresses(&header(raw, "bcc").unwrap_or_default()),
        in_reply_to: field("in-reply-to"),
        message_id: field("message-id"),
    }
}

/// The bare addresses of a header; a display name is dropped rather than
/// mis-parsed, because the envelope's structure is what the protocol needs.
fn addresses(value: &str) -> Vec<EnvAddress<'static>> {
    value
        .split(',')
        .filter_map(|part| {
            let inside = part
                .trim()
                .split_once('<')
                .and_then(|(_, rest)| rest.split_once('>'))
                .map_or(part.trim(), |(addr, _)| addr.trim());
            let (local, host) = inside.rsplit_once('@')?;
            (!local.is_empty() && !host.is_empty()).then(|| EnvAddress {
                name: NString(None),
                adl: NString(None),
                mailbox: literal_string(local.trim_matches('"').as_bytes()),
                host: literal_string(host.trim().as_bytes()),
            })
        })
        .collect()
}

/// The message's internal date: its `Date:` header when the protocol can
/// carry it, else the epoch (`INTERNALDATE` is mandatory, and a maildir keeps
/// no arrival stamp a rename would preserve).
fn internal_date(raw: &[u8]) -> DateTime {
    let epoch = || {
        let at = chrono::DateTime::from_timestamp(0, 0).expect("epoch is representable");
        DateTime::try_from(at.fixed_offset()).expect("the epoch is a legal IMAP date")
    };
    header(raw, "date")
        .and_then(|value| {
            chrono::DateTime::parse_from_str(value.trim(), "%a, %d %b %Y %H:%M:%S %z").ok()
        })
        .and_then(|at| DateTime::try_from(at).ok())
        .unwrap_or_else(epoch)
}

/// What a `SEARCH` key is answered from.
pub(crate) struct SearchContext {
    pub(crate) seq: u32,
    pub(crate) uid: u32,
    pub(crate) flags: Flags,
    pub(crate) unseen: bool,
    pub(crate) recent: bool,
    pub(crate) size: u64,
}

/// Whether one `SEARCH` key matches. A key this server cannot answer is *not
/// matching* rather than an error: a client asking for a date search gets an
/// empty answer it can retry differently, not a closed connection.
pub(crate) fn matches_key(key: &SearchKey<'_>, ctx: &SearchContext, raw: &[u8]) -> bool {
    let flag = |wanted: bool, set: bool| if wanted { set } else { !set };
    match key {
        SearchKey::And(keys) => keys
            .clone()
            .into_inner()
            .iter()
            .all(|key| matches_key(key, ctx, raw)),
        SearchKey::Or(a, b) => matches_key(a, ctx, raw) || matches_key(b, ctx, raw),
        SearchKey::Not(key) => !matches_key(key, ctx, raw),
        SearchKey::All => true,
        SearchKey::Seen => ctx.flags.seen,
        SearchKey::Unseen => ctx.unseen,
        SearchKey::Flagged => ctx.flags.flagged,
        SearchKey::Unflagged => !ctx.flags.flagged,
        SearchKey::Deleted => ctx.flags.trashed,
        SearchKey::Undeleted => !ctx.flags.trashed,
        SearchKey::Draft => ctx.flags.draft,
        SearchKey::Undraft => !ctx.flags.draft,
        SearchKey::Recent => ctx.recent,
        SearchKey::Old => !ctx.recent,
        SearchKey::New => ctx.recent && ctx.unseen,
        // The layout keeps no \Answered state, so "none" and its negation
        // "all" are the only honest answers.
        SearchKey::Answered => false,
        SearchKey::Unanswered => true,
        SearchKey::Keyword(atom) => keyword(atom.as_ref(), ctx.flags),
        SearchKey::Unkeyword(atom) => !keyword(atom.as_ref(), ctx.flags),
        SearchKey::SequenceSet(set) => set
            .iter(Strategy::Naive {
                largest: non_zero(ctx.seq),
            })
            .any(|n| n.get() == ctx.seq),
        SearchKey::Uid(set) => set
            .iter(Strategy::Naive {
                largest: non_zero(ctx.uid),
            })
            .any(|n| n.get() == ctx.uid),
        SearchKey::Larger(bytes) => ctx.size > u64::from(*bytes),
        SearchKey::Smaller(bytes) => ctx.size < u64::from(*bytes),
        SearchKey::Header(field, value) => {
            let field = String::from_utf8_lossy(field.as_ref()).to_ascii_lowercase();
            header(raw, &field).is_some_and(|text| contains(text.as_bytes(), value.as_ref()))
        }
        SearchKey::From(value) => header_contains(raw, "from", value.as_ref()),
        SearchKey::To(value) => header_contains(raw, "to", value.as_ref()),
        SearchKey::Cc(value) => header_contains(raw, "cc", value.as_ref()),
        SearchKey::Bcc(value) => header_contains(raw, "bcc", value.as_ref()),
        SearchKey::Subject(value) => header_contains(raw, "subject", value.as_ref()),
        SearchKey::Body(value) => contains(body_of(raw), value.as_ref()),
        SearchKey::Text(value) => contains(raw, value.as_ref()),
        _ => flag(false, false) && false,
    }
}
