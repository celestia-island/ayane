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

/// One row of the inbox listing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EnvelopeRow {
    /// IMAP UID within the mailbox (stable across sessions).
    pub uid: u32,
    /// First `From` address, when the envelope carried one.
    pub from: Option<String>,
    /// Subject (decoded as delivered by the server).
    pub subject: Option<String>,
    /// `\Seen` flag state.
    pub seen: bool,
    /// RFC 5322 size in bytes.
    pub size: u32,
}

/// Where a fetch should land the `\Seen` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkSeen {
    /// Fetch with BODY.PEEK and leave flags untouched.
    No,
    /// Fetch and mark the message seen.
    Yes,
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
            let mailbox_data = session
                .select(mailbox)
                .await
                .map_err(|e| ClientError::Imap(e.to_string()))?;
            let total = mailbox_data.exists;
            if total == 0 {
                return Ok(Vec::new());
            }
            let start = total.saturating_sub(limit as u32).max(1);
            let mut fetches = session
                .fetch(
                    format!("{start}:{total}"),
                    "(UID FLAGS ENVELOPE RFC822.SIZE)",
                )
                .await
                .map_err(|e| ClientError::Imap(e.to_string()))?;
            let mut rows = Vec::new();
            while let Some(item) = fetches.next().await {
                let fetch = item.map_err(|e| ClientError::Imap(e.to_string()))?;
                let Some(uid) = fetch.uid else { continue };
                let envelope = fetch.envelope();
                let from = envelope.and_then(|env| {
                    env.from.as_ref().and_then(|list| list.first()).map(|mb| {
                        match (&mb.mailbox, &mb.host) {
                            (Some(m), Some(h)) => format!(
                                "{}@{}",
                                String::from_utf8_lossy(m),
                                String::from_utf8_lossy(h)
                            ),
                            (Some(m), None) => String::from_utf8_lossy(m).into_owned(),
                            _ => String::new(),
                        }
                    })
                });
                let subject = envelope
                    .and_then(|env| env.subject.as_ref())
                    .map(|s| String::from_utf8_lossy(s).into_owned());
                let seen = fetch.flags().any(|f| f == async_imap::types::Flag::Seen);
                rows.push(EnvelopeRow {
                    uid,
                    from,
                    subject,
                    seen,
                    size: fetch.size.unwrap_or(0),
                });
            }
            rows.sort_by_key(|row| std::cmp::Reverse(row.uid));
            Ok(rows)
        }
        .await;

        let _ = session.logout().await;
        rows
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
                .append(mailbox, Some("\\Seen"), None, content)
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
