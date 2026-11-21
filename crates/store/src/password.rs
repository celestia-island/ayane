//! Account password hashing for Dovecot.
//!
//! Dovecot reads the rendered `passwd` file, so hashes must be in a scheme it
//! understands. SHA512-CRYPT (`$6$…`, the libcrypt scheme) is chosen over
//! fancier schemes deliberately: every Dovecot build verifies it with no extra
//! userspace libraries, and the `{SHA512-CRYPT}` prefix makes the scheme
//! self-describing inside the file. The modular-crypt string itself is built by
//! the `sha-crypt` crate (RustCrypto) so the encoding can never drift from the
//! reference implementation.

use sha_crypt::{Algorithm, CustomizedPasswordHasher, Params, PasswordVerifier, ShaCrypt};

/// The Dovecot scheme prefix used in the rendered passwd file.
pub const SCHEME_PREFIX: &str = "{SHA512-CRYPT}";

/// The SHA512-CRYPT round count (10,000 ≈ 10 ms: slow enough to blunt offline
/// cracking, fast enough that provisioning a handful of accounts is instant).
const ROUNDS: u32 = 10_000;

/// Salt length in raw bytes. 12 bytes encode to exactly 16 crypt-base64
/// characters — the SHA512-CRYPT maximum; longer salts are silently truncated
/// by glibc and rejected outright by stricter verifiers (Dovecot).
const SALT_BYTES: usize = 12;

/// Why hashing or verification failed.
#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    /// The underlying SHA512-CRYPT routine rejected its input.
    #[error("sha512-crypt: {0}")]
    Crypt(String),
    /// The stored hash is not a SHA512-CRYPT hash.
    #[error("unsupported hash scheme: {0}")]
    Scheme(String),
}

/// Hash a plaintext into a ready-to-render Dovecot password string.
///
/// # Errors
///
/// Returns [`PasswordError`] when the crypt routine fails (e.g. OS entropy is
/// unavailable).
pub fn hash_password(plain: &str) -> Result<String, PasswordError> {
    let params = Params::new(ROUNDS).map_err(|e| PasswordError::Crypt(e.to_string()))?;
    let mut salt = [0u8; SALT_BYTES];
    getrandom::fill(&mut salt).map_err(|e| PasswordError::Crypt(e.to_string()))?;
    let hasher = ShaCrypt::new(Algorithm::Sha512Crypt, params);
    let hashed = hasher
        .hash_password_customized(plain.as_bytes(), &salt, None, None, params)
        .map_err(|e| PasswordError::Crypt(e.to_string()))?;
    Ok(format!("{SCHEME_PREFIX}{hashed}"))
}

/// Verify a plaintext against a rendered Dovecot password string.
///
/// # Errors
///
/// Returns [`PasswordError`] when the hash is malformed, uses another scheme,
/// or simply does not match (callers only need "yes or no", and leaking which
/// side failed is not useful here).
pub fn verify_password(plain: &str, stored: &str) -> Result<(), PasswordError> {
    let hashed = stored
        .strip_prefix(SCHEME_PREFIX)
        .ok_or_else(|| PasswordError::Scheme(stored.chars().take(24).collect::<String>()))?;
    ShaCrypt::SHA512
        .verify_password(plain.as_bytes(), hashed)
        .map_err(|e| PasswordError::Crypt(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salt_encodes_to_the_spec_maximum_of_16_chars() {
        let stored = hash_password("x").expect("hash");
        let salt = stored
            .strip_prefix("{SHA512-CRYPT}$6$rounds=10000$")
            .and_then(|rest| rest.split('$').next())
            .expect("salt segment");
        assert_eq!(salt.len(), 16, "salt {salt}");
    }

    #[test]
    fn hashes_carry_the_dovecot_scheme_prefix() {
        let stored = hash_password("correct horse battery staple").expect("hash");
        assert!(
            stored.starts_with("{SHA512-CRYPT}$6$rounds=10000$"),
            "got {stored}"
        );
    }

    #[test]
    fn verifies_the_right_password_and_rejects_the_wrong_one() {
        let stored = hash_password("s3cret!").expect("hash");
        assert!(verify_password("s3cret!", &stored).is_ok());
        assert!(verify_password("wrong", &stored).is_err());
    }

    #[test]
    fn every_hash_is_salted() {
        let a = hash_password("same input").expect("hash a");
        let b = hash_password("same input").expect("hash b");
        assert_ne!(a, b, "identical plaintexts must produce different hashes");
        assert!(verify_password("same input", &a).is_ok());
        assert!(verify_password("same input", &b).is_ok());
    }

    #[test]
    fn rejects_foreign_schemes() {
        assert!(matches!(
            verify_password("x", "{PLAIN}abc"),
            Err(PasswordError::Scheme(_))
        ));
    }
}
