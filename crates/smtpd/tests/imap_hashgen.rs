//! Writes a `{SHA512-CRYPT}` hash to stdout, for the `imaplib` end-to-end run.
//!
//! `e2e/imap_imaplib.py` starts `ayane-smtpd --imap` with a `--password-hashes`
//! file, and that file's entries are `{SHA512-CRYPT}$6$rounds=…` — the shape
//! [`ayane_store::password::hash_password`] mints and
//! [`ayane_store::password::verify_password`] checks. Producing one from a
//! re-implementation of that algorithm in Python is a second implementation to
//! get wrong (and one did, repeatedly, while this was written); asking this
//! crate for it makes the fixture the same code path the store uses.
//!
//! ```text
//! cargo test -p ayane-smtpd --test imap_hashgen -- '<password>' > passwd-hash
//! ```
//!
//! The password arrives as the first argument, so it never sits in a source
//! file or a shell history entry of the repository. No argument at all is not
//! a failure: a plain `cargo test --workspace` runs every test binary, and this
//! one says what it is for and succeeds.

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(password) = args.next() else {
        println!("imap_hashgen: pass a password to print its {{SHA512-CRYPT}} hash");
        return;
    };
    match ayane_store::password::hash_password(&password) {
        Ok(hash) => println!("{hash}"),
        Err(err) => {
            eprintln!("cannot hash: {err}");
            std::process::exit(1);
        }
    }
}
