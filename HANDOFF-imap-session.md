# HANDOFF — IMAP session state machine (worktree `ayane/smtpd-imap-session`)

## Where things are

- Module: `crates/smtpd/src/imap_session.rs` (1,912 lines after rustfmt — **the <500-line
  cap is NOT met**; see "What is wrong" below).
- Tests: `crates/smtpd/src/imap_session/tests.rs` (unit, 19 tests) and
  `crates/smtpd/tests/imap_framing.rs` (5 literal-framing tests). All 24 pass.
- Deps added: `imap-codec = { version = "^1", features = ["starttls"] }` in
  `crates/smtpd/Cargo.toml` (the crates.io 1.0.0 line in this workspace's registry cache —
  its API differs from the GitHub `main` branch, and its `fragmentizer` module does not
  exist in 1.0.0). Registered with `pub mod imap_session;` in `lib.rs`.
- Nothing is committed, nothing pushed. `git status --porcelain` in the worktree:
  `M Cargo.lock`, `M crates/smtpd/Cargo.toml`, `M crates/smtpd/src/lib.rs`,
  `?? crates/smtpd/src/imap_session.rs`, `?? crates/smtpd/src/imap_session/`,
  `?? crates/smtpd/tests/imap_framing.rs`.
- Claim held: repo `ayane`, domain `imap-session`,
  `CLAIM_TOKEN=4639d0a95f703c2fe5739918`.

## What is verified today

`cargo test -p ayane-smtpd --lib imap_session` → 19 passed.
`cargo test -p ayane-smtpd --test imap_framing` → 5 passed.

The 19 unit tests cover: password refused while `Transport::Clear` and the verifier never
called; password checked over TLS; another account's valid password cannot open this
mailbox; commands before `LOGIN` refused; second `LOGIN` refused; full four-state lifecycle;
`EXAMINE` refuses STORE/EXPUNGE/COPY/MOVE and changes nothing on disk; an unimplemented
command is named in its `BAD`; a UID survives a flag change and the `new/`→`cur/` move; a
delivery landing later gets the next UID and a second session agrees; UIDs are never
reassigned and the watermark only grows; a corrupt `ayane-uidlist` line is skipped; a
sequence list is UID-ordered and `EXPUNGE` renumbers; `APPEND` stores the literal verbatim
with no UIDPLUS claim; `BODY[]` sets `\Seen` but `BODY.PEEK[]` does not; `ENVELOPE` fields.

The 5 framing tests cover: an announcement as a buffer suffix (`{28}`, `{28+}`, `{}` and a
plain line); the reader refuses a stream that ends mid-literal; one command per call from a
stream holding two; a malformed line refused by its tag; EOF.

## What is wrong

1. **Size.** 1,912 lines, and the cap is <500. The file is genuinely linear: a UidMap, a
   state machine, 15 command handlers, protocol rendering (`render_item`, `envelope`,
   `matches_key`), and the literal reader. It has to be split — but a split needs
   `pub(crate)` types across modules and was not done here.
2. **Four real bugs were found and fixed by the tests** (documented here so a rewrite does
   not reintroduce them):
   - the literal announcement must be detected as a **suffix of the buffer** (bare
     `…{28}` or with its CRLF) and read **byte-at-a-time**, or a read that happens to
     return the octets behind the announcement completes the command without ever
     sending `+`;
   - `str::strip_suffix` against a CRLF literal silently no-ops in this toolchain (verified
     with `rustc -O` standalone); that is what produced several of the phantom failures.
     Use `pending.strip_suffix(b"\r\n")` on a **byte** slice, not a `str`.
   - `EXPUNGE` numbers must be counted against the shrinking list, not the original.
   - `UIDVALIDITY` from inode+ctime can repeat for a recreated directory on tmpfs; the test
     only asserts it is never 0 and stable under a child being added.
3. Also found: `maildir_reader::tests::a_starred_roster_merges_folders_newest_first` is
   flaky under parallel load (fails in a full-crate run, passes in isolation and in three
   consecutive full `--lib` runs). It is pre-existing, not caused by this work.

## What is missing

- `cargo doc`, workspace-wide `cargo test`, `cargo-deny`, `cred_scan`, offline+online
  gates, mutation self-check, the Python `imaplib` end-to-end run (needs the driver in
  `crate::server`, which does not exist yet), and the commit.
- The <500-line split.
