# Test fixtures

## Verification (DKIM over the raw bytes)

`rfc6376-002.eml` / `rfc6376-002.key` are the pair of **RFC 6376 Appendix A.2**:
a public test vector whose `example.com` key the RFC itself publishes, so
nobody's private mail is in here and nothing in the tree is a credential.
`tests/verify.rs` and `tests/trust.rs` load the key into a fixed zone, so the
DKIM result is the RFC's own signature checked against the RFC's own key, with
no network.

The fixture carries the line endings it was published with (LF); the tests
convert them to CRLF once before hashing, because `simple` canonicalization is
exact about the body.

Every other verification fixture is built in-process from `mail-auth`'s own
signers — an Ed25519 key generated per test, an ARC chain sealed with it, a
DMARC record written as text — so a "pass" there is about this crate's
verifier, not about a captured message that happens to still match.

## STARTTLS (the listener tests)

`test-cert.pem` / `test-key.pem` are a **throwaway self-signed pair** generated
for the listener tests only:

```
[req]
distinguished_name = dn
prompt = no
x509_extensions = v3
[dn]
CN = mx.test
[v3]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:mx.test

openssl req -x509 -newkey rsa:2048 -keyout test-key.pem -out test-cert.pem \
    -days 3650 -nodes -config ext.cnf
```

`CA:FALSE` matters: rustls refuses a certificate that is a CA as an end
entity (`CaUsedAsEndEntity`), which is what a bare `-subj` self-signed pair is.

It is not a credential: it authenticates `mx.test` inside the test process and
nothing else, and every test trusts it explicitly. It exists so the STARTTLS
path is exercised over a real rustls handshake instead of being mocked.
