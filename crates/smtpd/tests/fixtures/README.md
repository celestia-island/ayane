`rfc6376-002.eml` / `rfc6376-002.key` are the pair of **RFC 6376 Appendix A.2**:
a public test vector whose `example.com` key the RFC itself publishes, so
nobody's private mail is in here and nothing in the tree is a credential.
`tests/verify.rs` loads the key into a fixed zone, so the DKIM result is the
RFC's own signature checked against the RFC's own key, with no network.

The fixture carries the line endings it was published with (LF); the test
converts them to CRLF once before hashing, because `simple` canonicalization is
exact about the body.

Every other fixture is built in-process from `mail-auth`'s own signers — an
Ed25519 key generated per test, an ARC chain sealed with it, a DMARC record
written as text — so a "pass" there is about this crate's verifier, not about a
captured message that happens to still match.
