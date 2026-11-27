# End-to-end drivers

Scripts here start the real binaries and talk to them over a real socket. They
complement `crates/*/tests`, which can only exercise one layer at a time.

## `imap_imaplib.py` — the IMAP listener, through `imaplib`

```sh
cargo build -p ayane-smtpd
python3 e2e/imap_imaplib.py
```

It starts `ayane-smtpd --imap` on a loopback port with this repository's
throwaway `crates/smtpd/tests/fixtures/test-{cert,key}.pem` (whose SAN is
`mx.test`), a scratch mail root holding one message, and a `--password-hashes`
file whose entry comes from the store's own hasher
(`cargo test -p ayane-smtpd --test imap_hashgen -- '<password>'`). Then it runs
the chain a mail client runs — `CAPABILITY` → `LOGIN` → `SELECT INBOX` →
`FETCH` → `STORE` → `SEARCH` (twice) → `LOGOUT` — and checks the message's
octets came back and that `STORE`'s flags are on disk as the maildir rename
they are.

Two details of `imaplib` shape the script, and both are worth knowing when
reading it (or writing another client):

- **`imaplib` cannot take a literal that is not at the end of a line.** Its
  reader only recognises `… {n}` when it is the last thing on the response
  line, and this server (like Dovecot) writes the rest of the FETCH item list
  behind the literal — `BODY[] {188}`, then octets, then `)`. So the FETCH
  answer is read here on purpose, with the socket's own octet counts, rather
  than through `imaplib`'s parser. The framing this script exercises is still
  the server's; only the *reading* is the test's.
- **`{n}` counts the literal and nothing else** (RFC 3501 §4.3), and the script
  asserts it: it reads exactly `n` octets and requires the next octet to be the
  one that closes the item list (`)`). A count that included the announcement
  would leave the reader seven octets early and it would see `{` instead.
- `mx.test` resolves nowhere, so the script patches `socket.getaddrinfo` for
  that one name to loopback: the TLS handshake is therefore verified against
  the certificate's real name (no `check_hostname = False`).

The password is this script's own invention and the passwd file lives in a
temporary directory. Nothing in here is a credential.
