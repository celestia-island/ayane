//! Submission (SMTP) and retrieval (IMAP) clients.
//!
//! These are the webmail's transport legs. ayane is always a *client* of the
//! mail stack: sending goes through Postfix submission with the account's own
//! credentials (so the queue, retries and authentication stay on the MTA), and
//! reading talks IMAP to Dovecot. Nothing here listens on a port.

use std::net::SocketAddr;

use futures_util::StreamExt;
use lettre::message::Message;

/// Why a client operation failed.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The TCP connection could not be established.
    #[error("connect: {0}")]
    Connect(String),
    /// The SMTP transaction failed (handshake, AUTH or DATA).
    #[error("smtp: {0}")]
    Smtp(String),
    /// The IMAP session failed (login, select or fetch).
    #[error("imap: {0}")]
    Imap(String),
}

/// A Postfix submission endpoint (plain AUTH on the internal network; TLS is
/// terminated by the reverse proxy in a real deployment).
#[derive(Debug, Clone)]
pub struct Submission {
    /// Host of the submission listener.
    pub host: String,
    /// Port of the submission listener.
    pub port: u16,
}

impl Submission {
    /// Build a submission endpoint from a socket address.
    #[must_use]
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            host: addr.ip().to_string(),
            port: addr.port(),
        }
    }

    /// Send `message`, authenticating as `username`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when the connection, AUTH or DATA phase fails.
    pub async fn send(
        &self,
        username: &str,
        password: &str,
        message: Message,
    ) -> Result<(), ClientError> {
        let raw = crate::compose::render(&message);
        let envelope = message.envelope().clone();
        let from = envelope.from().map(|a| a.to_string()).unwrap_or_default();
        let recipients: Vec<String> = envelope.to().iter().map(|a| a.to_string()).collect();
        let rcpt_refs: Vec<&str> = recipients.iter().map(String::as_str).collect();
        crate::smtp::submit_plain(
            &format!("{}:{}", self.host, self.port),
            username,
            password,
            &from,
            &rcpt_refs,
            &raw,
        )
        .await
        .map_err(|e| ClientError::Smtp(e.to_string()))
    }
}

impl Submission {
    /// Send `message` without authenticating, as a foreign MTA would on port
    /// 25. Used to exercise inbound policy (the deny list) in tests.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when the connection or DATA phase fails —
    /// including policy rejections, which surface as SMTP error strings.
    pub async fn send_unauthenticated(&self, message: Message) -> Result<(), ClientError> {
        let raw = crate::compose::render(&message);
        let envelope = message.envelope().clone();
        let from = envelope.from().map(|a| a.to_string()).unwrap_or_default();
        let recipients: Vec<String> = envelope.to().iter().map(|a| a.to_string()).collect();
        let rcpt_refs: Vec<&str> = recipients.iter().map(String::as_str).collect();
        crate::smtp::submit_plain(
            &format!("{}:{}", self.host, self.port),
            "",
            "",
            &from,
            &rcpt_refs,
            &raw,
        )
        .await
        .map_err(|e| ClientError::Smtp(e.to_string()))
    }
}

/// What an inbox overview contains.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InboxOverview {
    /// The mailbox's EXISTS count at SELECT time.
    pub exists: usize,
    /// ENVELOPE subjects in sequence order (empty string when absent).
    pub subjects: Vec<String>,
}

impl InboxOverview {
    /// Whether any message subject contains `marker`.
    #[must_use]
    pub fn has_subject_containing(&self, marker: &str) -> bool {
        self.subjects.iter().any(|s| s.contains(marker))
    }
}

/// A Dovecot IMAP endpoint.
#[derive(Debug, Clone)]
pub struct Imap {
    /// Host of the IMAP listener.
    pub host: String,
    /// Port of the IMAP listener.
    pub port: u16,
}

impl Imap {
    /// Build an IMAP endpoint from a socket address.
    #[must_use]
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            host: addr.ip().to_string(),
            port: addr.port(),
        }
    }

    /// Log in and summarise INBOX (message count + ENVELOPE subjects).
    ///
    /// Always logs out before returning.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when connect, login, SELECT or FETCH fails.
    pub async fn inbox_overview(
        &self,
        username: &str,
        password: &str,
    ) -> Result<InboxOverview, ClientError> {
        let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|e| ClientError::Connect(e.to_string()))?;
        let client = async_imap::Client::new(tcp);
        let mut session = client
            .login(username, password)
            .await
            .map_err(|(e, _): (async_imap::error::Error, _)| ClientError::Imap(e.to_string()))?;

        let overview = async {
            let mailbox = session
                .select("INBOX")
                .await
                .map_err(|e| ClientError::Imap(e.to_string()))?;
            let mut subjects = Vec::new();
            let mut fetches = session
                .fetch("1:*", "(ENVELOPE)")
                .await
                .map_err(|e| ClientError::Imap(e.to_string()))?;
            while let Some(item) = fetches.next().await {
                let fetch = item.map_err(|e| ClientError::Imap(e.to_string()))?;
                if let Some(envelope) = fetch.envelope() {
                    let subject = envelope
                        .subject
                        .as_ref()
                        .map(|s| String::from_utf8_lossy(s).into_owned())
                        .unwrap_or_default();
                    subjects.push(subject);
                }
            }
            Ok(InboxOverview {
                exists: mailbox.exists as usize,
                subjects,
            })
        }
        .await;

        // Best effort: the session is useless after a broken stream anyway.
        let _ = session.logout().await;
        overview
    }
}

// ── Webmail read path ─────────────────────────────────────────────────────

/// A mailbox listing: the newest `limit` messages plus the mailbox's
/// authoritative EXISTS count and unread count (the "共 N 条" denominator
/// and the 收件箱 badge behind a paged list — the delivered page is a
/// prefix, never the whole mailbox).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MailboxListing {
    /// Total messages the mailbox holds (IMAP EXISTS at select time).
    pub total: u32,
    /// Messages without `\Seen` (IMAP STATUS UNSEEN count).
    pub unread: u32,
    /// The newest messages, newest first.
    pub messages: Vec<EnvelopeRow>,
}

/// One row of the inbox listing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EnvelopeRow {
    /// IMAP UID within the mailbox (stable across sessions).
    pub uid: u32,
    /// The mailbox this row came from (the starred roster merges several).
    pub mailbox: String,
    /// First `From` address, when the envelope carried one.
    pub from: Option<String>,
    /// Subject (decoded as delivered by the server).
    pub subject: Option<String>,
    /// `\Seen` flag state.
    pub seen: bool,
    /// `\Flagged` (starred) flag state.
    pub flagged: bool,
    /// Opening lines of the text body (whitespace collapsed, truncated)
    /// for the roster's preview line — `None` when the fetch carried no
    /// usable text head.
    pub preview: Option<String>,
    /// Server INTERNALDATE rendered as RFC 3339 (offset preserved), when
    /// the server returned one. Drives the webmail's date column and the
    /// 今天/昨天/更早 swimlanes.
    pub date: Option<String>,
}

/// Where a fetch should land the `\Seen` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkSeen {
    /// Fetch with BODY.PEEK and leave flags untouched.
    No,
    /// Fetch and mark the message seen.
    Yes,
}

/// Build one listing row from a FETCH item; `None` when the server did not
/// name a UID (nothing to address operations against).
fn row_from_fetch(fetch: &async_imap::types::Fetch, mailbox: &str) -> Option<EnvelopeRow> {
    let uid = fetch.uid?;
    let envelope = fetch.envelope();
    let from = envelope.and_then(|env| {
        env.from
            .as_ref()
            .and_then(|list| list.first())
            .map(|mb| match (&mb.mailbox, &mb.host) {
                (Some(m), Some(h)) => format!(
                    "{}@{}",
                    String::from_utf8_lossy(m),
                    String::from_utf8_lossy(h)
                ),
                (Some(m), None) => String::from_utf8_lossy(m).into_owned(),
                _ => String::new(),
            })
    });
    let subject = envelope
        .and_then(|env| env.subject.as_ref())
        .map(|s| String::from_utf8_lossy(s).into_owned());
    let mut seen = false;
    let mut flagged = false;
    for flag in fetch.flags() {
        if flag == async_imap::types::Flag::Seen {
            seen = true;
        }
        if flag == async_imap::types::Flag::Flagged {
            flagged = true;
        }
    }
    Some(EnvelopeRow {
        uid,
        mailbox: mailbox.to_owned(),
        from,
        subject,
        seen,
        flagged,
        preview: preview_from_head(fetch.body()),
        date: fetch.internal_date().map(|d| d.to_rfc3339()),
    })
}

/// The roster's preview line from a text-body head: skip quoted reply
/// headers and leading blank lines, collapse the run of whitespace a
/// wrapped plain-text paragraph carries, and cut on a character boundary
/// just past two lines' worth. HTML part bytes render as tag soup — a
/// head without a clean text line is dropped (`None`) rather than shown.
fn preview_from_head(head: Option<&[u8]>) -> Option<String> {
    let head = head?;
    let text = String::from_utf8_lossy(head);
    let mut line = String::new();
    for raw in text.lines() {
        let trimmed = raw.trim();
        // Blank and quoted-reply lines are structure, not content: skip
        // them wherever they run (a head often opens with a wrapped
        // sentence, then the quote of what it answers — the author's
        // words are what the roster previews).
        if trimmed.is_empty() || trimmed.starts_with('>') {
            continue;
        }
        let needs = line.chars().count() + trimmed.chars().count() + 1;
        if needs > 160 {
            break;
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(trimmed);
        if line.chars().count() >= 80 {
            break;
        }
    }
    // A line must read as prose before it earns the preview: an HTML
    // part's tag soup, a bare `Content-…` header line, a base64 run —
    // all drop out (`None`) rather than render as junk under the subject.
    let prose = !line.is_empty()
        && !line.contains('<')
        && !line.contains("Content-")
        && line.chars().all(|c| c.is_alphanumeric() || c.is_whitespace() || PREVIEW_PUNCT.contains(c));
    let mut out = line;
    if out.chars().count() > 180 {
        out = out.chars().take(180).collect::<String>();
        // Never split inside a multi-byte char: drop to the boundary.
        while !out.is_char_boundary(out.len()) {
            out.pop();
        }
    }
    prose.then_some(out)
}

/// Punctuation a plain-text sentence may carry and still read as prose.
const PREVIEW_PUNCT: &str = ".,;:!?'\"()[]{}%+-=/@#&*_ ~—…、，。：；！？「」『』（）";

#[cfg(test)]
mod preview_tests {
    use super::preview_from_head;

    #[test]
    fn skips_quotes_and_collapses_wrapping() {
        let head = b"> On Mon, someone wrote:\r\n> quoted line\r\n\r\nHello,\r\n\r\nthis wrapped\r\nparagraph keeps going.\r\n";
        let preview = preview_from_head(Some(head)).expect("a usable head");
        assert_eq!(preview, "Hello, this wrapped paragraph keeps going.");
    }

    #[test]
    fn html_soup_drops_out() {
        let head = b"<html><body><p>Hi</p></body></html>";
        assert!(preview_from_head(Some(head)).is_none());
    }

    #[test]
    fn cuts_at_a_char_boundary() {
        // A wrapped CJK paragraph: two lines that together pass the 160-char
        // join budget, so the second one breaks off — and the 180-char cut
        // must still land on a boundary, never mid-char.
        let head = format!("{}\r\n{}{}", "段".repeat(120), "段".repeat(120), " tail");
        let preview = preview_from_head(Some(head.as_bytes())).expect("a usable head");
        assert!(preview.chars().count() <= 180, "got {}", preview.chars().count());
        assert!(preview.is_char_boundary(preview.len()));
        assert!(!preview.contains("tail"), "the overflow line never leaks in");
    }
}

impl Imap {
    /// List the newest `limit` messages of `mailbox`, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when connect, login, SELECT or FETCH fails.
    pub async fn list(
        &self,
        username: &str,
        password: &str,
        mailbox: &str,
        limit: usize,
    ) -> Result<MailboxListing, ClientError> {
        let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|e| ClientError::Connect(e.to_string()))?;
        let client = async_imap::Client::new(tcp);
        let mut session = client
            .login(username, password)
            .await
            .map_err(|(e, _): (async_imap::error::Error, _)| ClientError::Imap(e.to_string()))?;

        let rows = async {
            let mailbox_data = session
                .select(mailbox)
                .await
                .map_err(|e| ClientError::Imap(e.to_string()))?;
            let total = mailbox_data.exists;
            // The unread count rides STATUS UNSEEN (a COUNT, not the SELECT
            // first-unseen sequence) so the sidebar badge is honest even
            // when the delivered page holds fewer rows than the mailbox.
            let unread = session
                .status(mailbox, "(UNSEEN)")
                .await
                .ok()
                .and_then(|s| s.unseen)
                .unwrap_or(0);
            if total == 0 {
                return Ok(MailboxListing {
                    total: 0,
                    unread,
                    messages: Vec::new(),
                });
            }
            let start = total.saturating_sub(limit as u32).max(1);
            let mut fetches = session
                .fetch(
                    format!("{start}:{total}"),
                    "(UID FLAGS ENVELOPE INTERNALDATE BODY.PEEK[TEXT]<0.1024>)",
                )
                .await
                .map_err(|e| ClientError::Imap(e.to_string()))?;
            let mut rows = Vec::new();
            while let Some(item) = fetches.next().await {
                let fetch = item.map_err(|e| ClientError::Imap(e.to_string()))?;
                if let Some(row) = row_from_fetch(&fetch, mailbox) {
                    rows.push(row);
                }
            }
            rows.sort_by_key(|row| std::cmp::Reverse(row.uid));
            Ok(MailboxListing {
                total,
                unread,
                messages: rows,
            })
        }
        .await;

        let _ = session.logout().await;
        rows
    }

    /// List the newest flagged (starred) messages across `mailboxes`,
    /// merged newest first. The 已加星标 roster: a flag is per-message, so
    /// the view is a query over the real folders, not a folder of its own.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when connect, login or any SELECT/FETCH
    /// fails.
    pub async fn list_flagged(
        &self,
        username: &str,
        password: &str,
        mailboxes: &[&str],
        limit: usize,
    ) -> Result<Vec<EnvelopeRow>, ClientError> {
        let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|e| ClientError::Connect(e.to_string()))?;
        let client = async_imap::Client::new(tcp);
        let mut session = client
            .login(username, password)
            .await
            .map_err(|(e, _): (async_imap::error::Error, _)| ClientError::Imap(e.to_string()))?;

        let rows = async {
            let mut rows = Vec::new();
            for mailbox in mailboxes {
                // A mailbox that does not exist yet simply has no starred
                // mail — the merged roster skips it instead of failing.
                let Ok(mailbox_data) = session.select(*mailbox).await else {
                    continue;
                };
                if mailbox_data.exists == 0 {
                    continue;
                }
                let mut fetches = session
                    .fetch("1:*", "(UID FLAGS ENVELOPE RFC822.SIZE INTERNALDATE)")
                    .await
                    .map_err(|e| ClientError::Imap(e.to_string()))?;
                while let Some(item) = fetches.next().await {
                    let fetch = item.map_err(|e| ClientError::Imap(e.to_string()))?;
                    let Some(row) = row_from_fetch(&fetch, mailbox) else {
                        continue;
                    };
                    if row.flagged {
                        rows.push(row);
                    }
                }
            }
            rows.sort_by(|a, b| {
                b.date
                    .cmp(&a.date)
                    .then(std::cmp::Reverse(b.uid).cmp(&std::cmp::Reverse(a.uid)))
            });
            rows.truncate(limit);
            Ok(rows)
        }
        .await;

        let _ = session.logout().await;
        rows
    }

    /// Move one message to another mailbox by UID (the 删除 → 废纸篓 flow).
    /// The target is autocreated like every folder the webmail touches.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when connect, login, create, move or the
    /// 10 s guard fails.
    pub async fn move_to_mailbox(
        &self,
        username: &str,
        password: &str,
        from_mailbox: &str,
        uid: u32,
        to_mailbox: &str,
    ) -> Result<(), ClientError> {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
                .await
                .map_err(|e| ClientError::Connect(e.to_string()))?;
            let client = async_imap::Client::new(tcp);
            let mut session = client.login(username, password).await.map_err(
                |(e, _): (async_imap::error::Error, _)| ClientError::Imap(e.to_string()),
            )?;

            let _ = session.create(to_mailbox).await;
            let _ = session.select(from_mailbox).await;
            let result = session
                .uid_mv(uid.to_string(), to_mailbox)
                .await
                .map(|_| ())
                .map_err(|e| ClientError::Imap(e.to_string()));
            let _ = session.logout().await;
            result
        })
        .await
        .map_err(|_| ClientError::Imap("move timed out after 10s".to_owned()))?
    }

    /// Permanently delete one message by UID: mark `\Deleted` inside
    /// `mailbox` and EXPUNGE the mailbox (only this message carries the
    /// flag — the webmail never bulk-deletes). The 废纸篓's second step.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when connect, login, select, store, expunge
    /// or the 10 s guard fails.
    pub async fn purge_message(
        &self,
        username: &str,
        password: &str,
        mailbox: &str,
        uid: u32,
    ) -> Result<(), ClientError> {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
                .await
                .map_err(|e| ClientError::Connect(e.to_string()))?;
            let client = async_imap::Client::new(tcp);
            let mut session = client.login(username, password).await.map_err(
                |(e, _): (async_imap::error::Error, _)| ClientError::Imap(e.to_string()),
            )?;

            let result = async {
                session
                    .select(mailbox)
                    .await
                    .map_err(|e| ClientError::Imap(e.to_string()))?;
                // Drain the store stream fully in its own scope: it holds a
                // &mut session, and expunge below needs that back.
                {
                    let mut store = session
                        .uid_store(uid.to_string(), "+FLAGS.SILENT (\\Deleted)")
                        .await
                        .map_err(|e| ClientError::Imap(e.to_string()))?;
                    while let Some(item) = store.next().await {
                        item.map_err(|e| ClientError::Imap(e.to_string()))?;
                    }
                }
                let expunged = session
                    .expunge()
                    .await
                    .map_err(|e| ClientError::Imap(e.to_string()))?;
                tokio::pin!(expunged);
                while let Some(item) = expunged.next().await {
                    item.map_err(|e| ClientError::Imap(e.to_string()))?;
                }
                Ok(())
            }
            .await;
            let _ = session.logout().await;
            result
        })
        .await
        .map_err(|_| ClientError::Imap("purge timed out after 10s".to_owned()))?
    }

    /// Fetch one message's raw bytes by UID.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when connect, login, SELECT or the fetch
    /// fails; an empty body (missing message) also maps to [`ClientError`].
    pub async fn fetch_raw(
        &self,
        username: &str,
        password: &str,
        mailbox: &str,
        uid: u32,
        mark_seen: MarkSeen,
    ) -> Result<Vec<u8>, ClientError> {
        let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|e| ClientError::Connect(e.to_string()))?;
        let client = async_imap::Client::new(tcp);
        let mut session = client
            .login(username, password)
            .await
            .map_err(|(e, _): (async_imap::error::Error, _)| ClientError::Imap(e.to_string()))?;

        let raw = async {
            session
                .select(mailbox)
                .await
                .map_err(|e| ClientError::Imap(e.to_string()))?;
            if mark_seen == MarkSeen::Yes {
                let mut store = session
                    .uid_store(uid.to_string(), "+FLAGS.SILENT (\\Seen)")
                    .await
                    .map_err(|e| ClientError::Imap(e.to_string()))?;
                while let Some(item) = store.next().await {
                    item.map_err(|e| ClientError::Imap(e.to_string()))?;
                }
            }
            let mut fetches = session
                .uid_fetch(uid.to_string(), "(BODY.PEEK[])")
                .await
                .map_err(|e| ClientError::Imap(e.to_string()))?;
            let mut body = None;
            while let Some(item) = fetches.next().await {
                let fetch = item.map_err(|e| ClientError::Imap(e.to_string()))?;
                if fetch.uid == Some(uid) {
                    if let Some(bytes) = fetch.body() {
                        body = Some(bytes.to_vec());
                    }
                }
            }
            body.ok_or_else(|| ClientError::Imap(format!("uid {uid} not found in {mailbox}")))
        }
        .await;

        let _ = session.logout().await;
        raw
    }

    /// Append a sent copy to `mailbox` (typically `Sent`).
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when connect, login, SELECT-EXAMINE or
    /// APPEND fails.
    pub async fn append_to_mailbox(
        &self,
        username: &str,
        password: &str,
        mailbox: &str,
        flags: Option<&str>,
        content: &[u8],
    ) -> Result<(), ClientError> {
        // async-imap's APPEND deadlocks when the server rejects before the
        // literal continuation (Dovecot's "NO [TRYCREATE]"): a timeout keeps
        // any library misbehaviour from hanging a webmail request forever.
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
                .await
                .map_err(|e| ClientError::Connect(e.to_string()))?;
            let client = async_imap::Client::new(tcp);
            let mut session = client.login(username, password).await.map_err(
                |(e, _): (async_imap::error::Error, _)| ClientError::Imap(e.to_string()),
            )?;

            // Autocreate the target mailbox: appending to a missing folder
            // is the deadlock trigger above, and a mail service should keep
            // Sent alive anyway.
            let _ = session.create(mailbox).await;
            let result = session
                .append(mailbox, flags, None, content)
                .await
                .map_err(|e| ClientError::Imap(e.to_string()));
            let _ = session.logout().await;
            result
        })
        .await
        .map_err(|_| ClientError::Imap("append timed out after 10s".to_owned()))?
    }
}

impl Imap {
    /// Set or clear one flag set on a message by UID.
    ///
    /// `query` is a raw STORE modifier such as `+FLAGS.SILENT (\Seen)`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when connect, login, SELECT or STORE fails.
    pub async fn store_flag(
        &self,
        username: &str,
        password: &str,
        mailbox: &str,
        uid: u32,
        query: &str,
    ) -> Result<(), ClientError> {
        let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|e| ClientError::Connect(e.to_string()))?;
        let client = async_imap::Client::new(tcp);
        let mut session = client
            .login(username, password)
            .await
            .map_err(|(e, _): (async_imap::error::Error, _)| ClientError::Imap(e.to_string()))?;

        let result = async {
            session
                .select(mailbox)
                .await
                .map_err(|e| ClientError::Imap(e.to_string()))?;
            let mut store = session
                .uid_store(uid.to_string(), query)
                .await
                .map_err(|e| ClientError::Imap(e.to_string()))?;
            while let Some(item) = store.next().await {
                item.map_err(|e| ClientError::Imap(e.to_string()))?;
            }
            Ok(())
        }
        .await;

        let _ = session.logout().await;
        result
    }
}
