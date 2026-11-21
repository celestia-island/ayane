//! Persistent control-plane state.
//!
//! ayane is the single authority for the mail configuration, so its store is a
//! small embedded database rather than a second server to operate. The whole
//! desired state lives as **one atomic snapshot** — a single redb key holding a
//! msgpack-encoded [`StoredState`] — which makes every save transactional and
//! every load a consistent view. No partial states can ever be observed.
//!
//! The KV driver is `lacrymira-redb` (the family data access layer), so the
//! same store runs anywhere redb runs and gains the family's msgpack line
//! format for free.

use std::collections::HashMap;
use std::path::Path;

use ayane_proto::{Address, DesiredState};
use lacrymira::{Command, KvOp, Reply, Value};
use lacrymira_redb::RedbStore;

pub mod password;

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The underlying KV driver failed.
    #[error("store backend: {0}")]
    Backend(String),
    /// The snapshot could not be encoded or decoded.
    #[error("snapshot codec: {0}")]
    Codec(String),
}

/// Everything the control plane persists.
///
/// `desired` is the public, secret-free configuration (also what the API
/// returns); `password_hashes` maps account addresses to ready-to-use Dovecot
/// password strings (`{SHA512-CRYPT}$6$…`). Keeping the two in one snapshot
/// makes "account exists but has no hash" impossible once saved.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredState {
    /// The validated desired configuration.
    pub desired: DesiredState,
    /// Dovecot-format password hashes keyed by account address.
    pub password_hashes: HashMap<String, String>,
}

impl StoredState {
    /// An empty state (no domains, no accounts).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The Dovecot password hash for `address`, if the account exists.
    #[must_use]
    pub fn password_hash(&self, address: &Address) -> Option<&str> {
        self.password_hashes
            .get(address.as_str())
            .map(String::as_str)
    }
}

/// Persistent storage for [`StoredState`].
pub trait StateStore: Send + Sync {
    /// Load the snapshot (an empty state when nothing was ever saved).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend or the codec fails.
    fn load(&self) -> Result<StoredState, StoreError>;

    /// Atomically replace the snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend or the codec fails.
    fn save(&self, state: &StoredState) -> Result<(), StoreError>;
}

const STATE_KEY: &str = "state";

/// redb-backed [`StateStore`] through the lacrymira KV surface.
pub struct RedbStateStore {
    inner: RedbStore,
}

impl RedbStateStore {
    /// Open (or create) the database at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when redb cannot open or initialise the file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| StoreError::Backend(format!("create {}: {e}", parent.display())))?;
        }
        Ok(Self {
            inner: RedbStore::open(path).map_err(|e| StoreError::Backend(e.to_string()))?,
        })
    }

    fn execute_set(&self, value: &StoredState) -> Result<(), StoreError> {
        let bytes = rmp_serde::to_vec(value).map_err(|e| StoreError::Codec(e.to_string()))?;
        let reply = self
            .inner
            .execute(&Command::Kv {
                namespace: "ayane".to_owned(),
                op: KvOp::Set {
                    key: Value::Text(STATE_KEY.to_owned()),
                    value: Value::Bytes(bytes),
                },
            })
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        match reply {
            Reply::Unit => Ok(()),
            other => Err(StoreError::Backend(format!(
                "unexpected reply for Set: {other:?}"
            ))),
        }
    }
}

impl StateStore for RedbStateStore {
    fn load(&self) -> Result<StoredState, StoreError> {
        let reply = self
            .inner
            .execute(&Command::Kv {
                namespace: "ayane".to_owned(),
                op: KvOp::Get {
                    key: Value::Text(STATE_KEY.to_owned()),
                },
            })
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        match reply {
            Reply::Value(Some(Value::Bytes(bytes))) => {
                rmp_serde::from_slice(&bytes).map_err(|e| StoreError::Codec(e.to_string()))
            }
            Reply::Value(Some(other)) => Err(StoreError::Backend(format!(
                "state key holds a non-bytes value: {other:?}"
            ))),
            Reply::Value(None) => Ok(StoredState::empty()),
            other => Err(StoreError::Backend(format!(
                "unexpected reply for Get: {other:?}"
            ))),
        }
    }

    fn save(&self, state: &StoredState) -> Result<(), StoreError> {
        self.execute_set(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ayane_proto::{Account, MailDomain, Policy};

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ayane-store-{tag}-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn sample() -> StoredState {
        let address = Address::parse("alice@example.test").expect("address");
        let mut hashes = HashMap::new();
        hashes.insert(
            "alice@example.test".to_owned(),
            password::hash_password("correct horse battery staple").expect("hash"),
        );
        StoredState {
            desired: DesiredState {
                domains: vec![MailDomain {
                    name: "example.test".to_owned(),
                    catch_all: None,
                    enabled: true,
                }],
                accounts: vec![Account {
                    id: uuid::Uuid::new_v4(),
                    address,
                    display_name: "Alice".to_owned(),
                    quota_bytes: 0,
                }],
                aliases: Vec::new(),
                shared: Vec::new(),
                policy: Policy::default(),
            },
            password_hashes: hashes,
        }
    }

    #[test]
    fn roundtrips_through_the_database() {
        let path = temp_path("roundtrip").join("state.redb");
        let store = RedbStateStore::open(&path).expect("open");
        assert_eq!(store.load().expect("empty load"), StoredState::empty());
        let state = sample();
        store.save(&state).expect("save");
        assert_eq!(store.load().expect("load"), state);
    }

    #[test]
    fn persists_across_reopen() {
        let path = temp_path("reopen").join("state.redb");
        {
            let store = RedbStateStore::open(&path).expect("open");
            store.save(&sample()).expect("save");
        }
        let store = RedbStateStore::open(&path).expect("reopen");
        let loaded = store.load().expect("load");
        assert_eq!(loaded.desired.domains.len(), 1);
        assert!(loaded
            .password_hash(&Address::parse("alice@example.test").expect("address"))
            .is_some());
    }

    #[test]
    fn missing_hash_for_unknown_account_is_none() {
        let state = StoredState::empty();
        let address = Address::parse("nobody@example.test").expect("address");
        assert!(state.password_hash(&address).is_none());
    }
}
