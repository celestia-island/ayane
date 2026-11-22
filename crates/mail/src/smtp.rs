//! Minimal async SMTP submission client.
//!
//! Hand-rolled on purpose: the webmail only ever needs the plain
//! authenticated-submission conversation (connect → EHLO → AUTH PLAIN →
//! MAIL → RCPT → DATA), always against a loopback endpoint we operate
//! (the engine's internal port or the public 587/465 through a TLS
//! terminator). A full SMTP library pulled an async connection pool whose
//! first live use deadlocked with zero syscalls (see the send-leg
//! incident); this client is ~100 lines, every line observable.

use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// Why a submission failed.
#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    /// The TCP connection failed.
    #[error("connect: {0}")]
    Connect(String),
    /// The server refused a step (the reply line is included).
    #[error("smtp refused: {0}")]
    Rejected(String),
    /// I/O on the stream failed.
    #[error("io: {0}")]
    Io(String),
}

impl From<std::io::Error> for SubmitError {
    fn from(e: std::io::Error) -> Self {
        SubmitError::Io(e.to_string())
    }
}

/// Submit `message` (raw RFC 5322 bytes) as `user` over plaintext
/// authenticated submission at `addr`.
///
/// # Errors
///
/// Returns [`SubmitError`] on connect failure, an SMTP refusal (any
/// non-2xx/3-5x where 2xx/3xx is expected) or an I/O failure.
pub async fn submit_plain(
    addr: &str,
    user: &str,
    password: &str,
    from: &str,
    recipients: &[&str],
    message: &[u8],
) -> Result<(), SubmitError> {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| SubmitError::Connect(e.to_string()))?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    expect(&mut reader, 220, "greeting").await?;
    command(&mut writer, &mut reader, "EHLO ayane.local", 250).await?;

    let creds = base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{password}"));
    command(
        &mut writer,
        &mut reader,
        &format!("AUTH PLAIN {creds}"),
        235,
    )
    .await?;

    command(
        &mut writer,
        &mut reader,
        &format!("MAIL FROM:<{from}>"),
        250,
    )
    .await?;
    for rcpt in recipients {
        command(&mut writer, &mut reader, &format!("RCPT TO:<{rcpt}>"), 250).await?;
    }
    command(&mut writer, &mut reader, "DATA", 354).await?;

    // Dot-stuffing: a line starting with '.' gets one more.
    let mut stuffed = Vec::with_capacity(message.len() + 16);
    let mut at_line_start = true;
    for &byte in message {
        if at_line_start && byte == b'.' {
            stuffed.push(b'.');
        }
        stuffed.push(byte);
        at_line_start = byte == b'\n';
    }
    writer.write_all(&stuffed).await?;
    writer.write_all(b"\r\n.\r\n").await?;
    writer.flush().await?;
    expect(&mut reader, 250, "data accepted").await?;

    command(&mut writer, &mut reader, "QUIT", 221).await?;
    Ok(())
}

async fn command<W: AsyncWrite + Unpin, R: AsyncRead + Unpin>(
    writer: &mut W,
    reader: &mut BufReader<R>,
    line: &str,
    expected: u16,
) -> Result<(), SubmitError> {
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\r\n").await?;
    writer.flush().await?;
    let reply = read_reply(reader).await?;
    if code_of(&reply) == expected {
        Ok(())
    } else {
        Err(SubmitError::Rejected(format!("{line:?} → {reply}")))
    }
}

async fn expect<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    expected: u16,
    what: &str,
) -> Result<(), SubmitError> {
    let reply = read_reply(reader).await?;
    let code = code_of(&reply);
    if (400..600).contains(&code) || code != expected {
        return Err(SubmitError::Rejected(format!("{what}: {reply}")));
    }
    Ok(())
}

/// Read one (possibly multi-line) SMTP reply: `250-...` continues,
/// `250 ` terminates.
async fn read_reply<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<String, SubmitError> {
    let mut full = String::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(SubmitError::Io("connection closed mid-reply".into()));
        }
        let keep = line.trim_end_matches("\r\n");
        full.push_str(keep);
        // A 3-digit code followed by space (or a short line) ends the reply.
        if keep.len() >= 4 && keep.as_bytes()[3] == b' ' || keep.len() < 4 {
            return Ok(full);
        }
        full.push('\n');
    }
}

fn code_of(reply: &str) -> u16 {
    reply
        .get(0..3)
        .and_then(|digits| digits.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_of_parses_and_rejects() {
        assert_eq!(code_of("250 OK"), 250);
        assert_eq!(code_of("535 auth failed"), 535);
        assert_eq!(code_of("xx"), 0);
    }

    #[tokio::test]
    async fn submits_against_a_fake_server() {
        use tokio::io::{duplex, AsyncReadExt};
        // A scripted SMTP server: every expected step in, one reply out.
        let (mut server, client) = duplex(4096);
        let server_task = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            // The banner goes out FIRST; then the loop answers each client
            // line in order.
            let replies = [
                "250-fake\r\n250 AUTH PLAIN\r\n" as &str,
                "235 ok\r\n",
                "250 ok\r\n",
                "250 ok\r\n",
                "354 go\r\n",
                "250 queued as 1\r\n",
                "221 bye\r\n",
            ];
            server.write_all(b"220 fake ESMTP\r\n").await.unwrap();
            let mut buf = [0u8; 1024];
            for reply in replies {
                let n = server.read(&mut buf).await.unwrap_or(0);
                assert!(n > 0);
                server.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        let (client_r, client_w) = tokio::io::split(client);
        let mut reader = BufReader::new(client_r);
        let mut writer = client_w;
        let result = (async {
            expect(&mut reader, 220, "greeting").await?;
            command(&mut writer, &mut reader, "EHLO ayane.local", 250).await?;
            let creds = base64::engine::general_purpose::STANDARD.encode("\0u\0p");
            command(
                &mut writer,
                &mut reader,
                &format!("AUTH PLAIN {creds}"),
                235,
            )
            .await?;
            command(&mut writer, &mut reader, "MAIL FROM:<a@b>", 250).await?;
            command(&mut writer, &mut reader, "RCPT TO:<c@d>", 250).await?;
            command(&mut writer, &mut reader, "DATA", 354).await?;
            writer.write_all(b"hello\r\n.\r\n").await?;
            writer.flush().await?;
            expect(&mut reader, 250, "data").await?;
            command(&mut writer, &mut reader, "QUIT", 221).await?;
            Ok::<(), SubmitError>(())
        })
        .await;
        server_task.await.unwrap();
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn dot_stuffing_is_applied_by_the_caller() {
        // The stuffing lives inline in submit_plain; this pins the rule.
        let message = b".starts with dot\r\nnormal\r\n.\r\n";
        let mut stuffed = Vec::new();
        let mut at_line_start = true;
        for &b in message {
            if at_line_start && b == b'.' {
                stuffed.push(b'.');
            }
            stuffed.push(b);
            at_line_start = b == b'\n';
        }
        assert_eq!(stuffed, b"..starts with dot\r\nnormal\r\n..\r\n");
    }
}
