# Test fixtures

## TLS: the `mx.test` key pair

`mx-test-cert.pem` / `mx-test-key.pem` are a copy of
`crates/smtpd/tests/fixtures/test-cert.pem` / `test-key.pem`: a **self-signed
RSA-2048 certificate for `mx.test`**, generated offline with `openssl` and used
only by this crate's end-to-end test of the submission listener (the one that
proves a client can `STARTTLS`, `AUTH` against the store and send a message).

It is not a credential. `openssl req -x509 -newkey rsa:2048` made it, `CA:FALSE`
(the server verifies its own end-entity role), it has never been configured into
an instance, never served on a public port, and the private key is in the tree
because the fixture is worthless without it.

It is a **byte-for-byte copy** of `crates/smtpd/tests/fixtures/test-key.pem`, and
the copy exists because a crate cannot `include_str!` a *dependency's* test
directory: `ayane` depends on `ayane-smtpd`, not the other way round, so the
end-to-end test that drives a real `STARTTLS` handshake from this crate cannot
reach the smtpd fixture's path without re-generating a second key pair. Both
entries are registered in `_ledger/tool-exemptions.md` under the `cred_scan` PEM
rule.
