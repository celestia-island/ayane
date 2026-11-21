//! Submission (SMTP) and retrieval (IMAP) clients.
//!
//! These are the webmail's transport legs. ayane is always a *client* of the
//! mail stack: sending goes through Postfix submission with the account's own
//! credentials (so the queue, retries and authentication stay on the MTA), and
//! reading talks IMAP to Dovecot. Nothing here listens on a port.

use std::net::SocketAddr;

use futures_util::StreamExt;
use lettre::message::Message;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

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
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.host)
            .port(self.port)
            .credentials(Credentials::new(username.to_owned(), password.to_owned()))
            .build();
        mailer
            .send(message)
            .await
            .map(|_| ())
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
