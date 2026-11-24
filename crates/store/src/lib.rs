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
use chrono::{DateTime, Utc};
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
    /// A mutation was refused by a rule on the snapshot (the store keeps
    /// the check and the write in one locked step, so the rule lives here).
    #[error("snapshot rule: {0}")]
    Rejected(String),
}

/// One third-party identity linked to an own-domain mailbox.
///
/// The link is keyed by the provider's **subject** (its opaque, stable
/// account id) — never by an email address, which changes, is reassigned
/// and collides across realms. The mailbox side is the account's address:
/// the address is what stays stable in ayane (an account's `id` is minted
/// afresh by every whole-state replacement), and the account is always an
/// own-domain one, since ayane only administers its own domains.
///
/// No field is ever skipped on the wire: the snapshot is msgpack with
/// positional structs, so an omitted field would shift every field after
/// it. Absent values travel as `None`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExternalLink {
    /// The host's provider id as it names it (`github`, `google`).
    pub provider: String,
    /// The issuer URL for URL-addressed providers; `None` for opaque ones.
    #[serde(default)]
    pub issuer: Option<String>,
    /// The provider's stable subject for this account.
    pub subject: String,
    /// The linked account.
    pub address: Address,
    /// When the link was created.
    pub created_at: DateTime<Utc>,
    /// The last sign-in that arrived through this link, if any was recorded.
    #[serde(default)]
    pub last_login_at: Option<DateTime<Utc>>,
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
    /// Third-party identities linked to accounts ([`ExternalLink`]). Absent
    /// on snapshots written before federated sign-in: an empty list.
    #[serde(default)]
    pub external_identities: Vec<ExternalLink>,
}

/// One user-owned compose template.
///
/// Templates are personal data, not desired configuration: they live in
/// their own KV key so a template edit never rewrites the config snapshot
/// (and never triggers an apply diff).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Template {
    /// Stable identifier (UUID v4, minted by the server).
    pub id: String,
    /// Owner account address.
    pub owner: String,
    /// Human name shown in the template menu.
    pub name: String,
    /// Prefilled subject (`{…}` placeholders are the user's own convention).
    pub subject: String,
    /// Prefilled body.
    pub body: String,
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

    /// The credential a provider sign-in opens `address` with, when the
    /// server holds one for it.
    ///
    /// # Product rule (2026-11-24)
    ///
    /// ayane controls only its own mail domains. A foreign mailbox is at
    /// most signed in to *on behalf of* its owner and used as a forwarding
    /// node, whose credentials and some records are **cached on the
    /// server** — a user never re-enters the password of an already
    /// registered foreign mailbox after signing in. Such an account signs
    /// in through its provider and the session is minted with the cached
    /// credential directly, with no mailbox-password step.
    ///
    /// Returns `None` today: the account model has no cached-credential
    /// node yet. It is the single hook a future "forwarding node" account
    /// kind fills in; the session minting already branches on it.
    #[must_use]
    pub fn cached_credential(&self, address: &Address) -> Option<String> {
        let _ = address;
        None
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
    /// This is a WHOLE-SNAPSHOT replace and it bypasses the write lock: a
    /// caller that `load()`s, edits what it read and `save()`s it back
    /// races every other writer and silently drops whatever landed in
    /// between (a link made meanwhile, a grant flipped). Read-modify-write
    /// belongs in [`Self::update`]; `save` is for a snapshot built from
    /// scratch — seeding, a replacement prepared from the request alone.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend or the codec fails.
    fn save(&self, state: &StoredState) -> Result<(), StoreError>;

    /// Read-modify-write the snapshot under the store's write lock.
    ///
    /// `edit` runs exactly once, with the lock held, on the **latest**
    /// saved snapshot; when it returns `Ok` the result is saved before the
    /// lock is released, so two concurrent edits cannot overwrite each
    /// other's change (last-write-drops-the-other was a real race). An
    /// `Err` leaves the stored snapshot untouched. A rule that must hold
    /// for the written state belongs inside `edit` — that is what makes
    /// the check and the write one step.
    ///
    /// # Errors
    ///
    /// [`StoreError::Rejected`] (or any other variant) from `edit`, or a
    /// backend/codec failure.
    fn update(
        &self,
        edit: &mut dyn FnMut(&mut StoredState) -> Result<(), StoreError>,
    ) -> Result<(), StoreError>;

    /// List the compose templates owned by `owner` (name order).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend or the codec fails.
    fn list_templates(&self, owner: &str) -> Result<Vec<Template>, StoreError>;

    /// Insert or replace one template (the id decides).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend or the codec fails, or the
    /// id already belongs to a different owner.
    fn save_template(&self, template: &Template) -> Result<(), StoreError>;

    /// Delete one template owned by `owner`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend or the codec fails.
    fn delete_template(&self, owner: &str, id: &str) -> Result<(), StoreError>;

    /// The stored IMAP password for a shared mailbox (minting one when the
    /// mailbox has none yet). This is a MACHINE credential: generated by the
    /// server, shown to nobody, used only to open the shared mailbox over
    /// IMAP for a member session.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend or the codec fails.
    fn shared_imap_password(&self, address: &str) -> Result<String, StoreError>;
}

const STATE_KEY: &str = "state";
const TEMPLATES_KEY: &str = "templates";
/// Server-generated IMAP credentials for shared mailboxes, keyed by address.
/// Plaintext by necessity (the webmail must log into Dovecot as the shared
/// mailbox on the member's behalf), stored under the same 0600 discipline as
/// the sessions file and NEVER serialized into a state read.
const SHARED_IMAP_KEY: &str = "shared_imap";

/// redb-backed [`StateStore`] through the lacrymira KV surface.
pub struct RedbStateStore {
    inner: RedbStore,
    /// The templates key is read-modify-write; this lock makes concurrent
    /// owner saves atomic against each other (last-write-drops-the-other
    /// was a real race with two owners saving at once).
    templates_lock: std::sync::Mutex<()>,
    /// The same discipline for the state snapshot: every locked
    /// read-modify-write ([`StateStore::update`]) runs under this lock, so
    /// two edits (a link, a whole-state replacement) see each other.
    state_lock: std::sync::Mutex<()>,
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
            templates_lock: std::sync::Mutex::new(()),
            state_lock: std::sync::Mutex::new(()),
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

    fn load_shared_imap(&self) -> Result<std::collections::HashMap<String, String>, StoreError> {
        let reply = self
            .inner
            .execute(&Command::Kv {
                namespace: "ayane".to_owned(),
                op: KvOp::Get {
                    key: Value::Text(SHARED_IMAP_KEY.to_owned()),
                },
            })
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        match reply {
            Reply::Value(Some(Value::Bytes(bytes))) => {
                rmp_serde::from_slice(&bytes).map_err(|e| StoreError::Codec(e.to_string()))
            }
            Reply::Value(Some(other)) => Err(StoreError::Backend(format!(
                "shared imap key holds a non-bytes value: {other:?}"
            ))),
            Reply::Value(None) => Ok(std::collections::HashMap::new()),
            other => Err(StoreError::Backend(format!(
                "unexpected reply for Get: {other:?}"
            ))),
        }
    }

    fn load_templates(&self) -> Result<Vec<Template>, StoreError> {
        let reply = self
            .inner
            .execute(&Command::Kv {
                namespace: "ayane".to_owned(),
                op: KvOp::Get {
                    key: Value::Text(TEMPLATES_KEY.to_owned()),
                },
            })
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        match reply {
            Reply::Value(Some(Value::Bytes(bytes))) => {
                rmp_serde::from_slice(&bytes).map_err(|e| StoreError::Codec(e.to_string()))
            }
            Reply::Value(Some(other)) => Err(StoreError::Backend(format!(
                "templates key holds a non-bytes value: {other:?}"
            ))),
            Reply::Value(None) => Ok(Vec::new()),
            other => Err(StoreError::Backend(format!(
                "unexpected reply for Get: {other:?}"
            ))),
        }
    }

    fn execute_set_templates(&self, templates: &[Template]) -> Result<(), StoreError> {
        let bytes = rmp_serde::to_vec(templates).map_err(|e| StoreError::Codec(e.to_string()))?;
        let reply = self
            .inner
            .execute(&Command::Kv {
                namespace: "ayane".to_owned(),
                op: KvOp::Set {
                    key: Value::Text(TEMPLATES_KEY.to_owned()),
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

    fn update(
        &self,
        edit: &mut dyn FnMut(&mut StoredState) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        // One lock spans load → edit → save: the edit sees the latest
        // snapshot and nothing can slip in between the check it makes and
        // the write it performs. The closure must not call back into the
        // store (the lock is not reentrant).
        let _guard = self.state_lock.lock().expect("state mutex");
        let mut current = self.load()?;
        edit(&mut current)?;
        self.execute_set(&current)
    }

    fn list_templates(&self, owner: &str) -> Result<Vec<Template>, StoreError> {
        let mut templates = self.load_templates()?;
        templates.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
        templates.retain(|template| template.owner == owner);
        Ok(templates)
    }

    fn save_template(&self, template: &Template) -> Result<(), StoreError> {
        // The whole list rides one KV key: cap the payload so a single
        // template cannot grow the snapshot unboundedly.
        if template.name.len() > 200
            || template.subject.len() > 998
            || template.body.len() > 64 * 1024
        {
            return Err(StoreError::Backend(
                "template exceeds size limits".to_owned(),
            ));
        }
        let _guard = self.templates_lock.lock().expect("templates mutex");
        let mut templates = self.load_templates()?;
        // An id is single-owner: replacing another account's template would
        // leak its body across accounts.
        if let Some(existing) = templates
            .iter_mut()
            .find(|existing| existing.id == template.id)
        {
            if existing.owner != template.owner {
                return Err(StoreError::Backend(format!(
                    "template {} belongs to another account",
                    template.id
                )));
            }
            *existing = template.clone();
        } else {
            templates.push(template.clone());
        }
        self.execute_set_templates(&templates)
    }

    fn delete_template(&self, owner: &str, id: &str) -> Result<(), StoreError> {
        let _guard = self.templates_lock.lock().expect("templates mutex");
        let mut templates = self.load_templates()?;
        let before = templates.len();
        templates.retain(|template| !(template.id == id && template.owner == owner));
        if templates.len() == before {
            return Ok(());
        }
        self.execute_set_templates(&templates)
    }

    fn shared_imap_password(&self, address: &str) -> Result<String, StoreError> {
        let mut map = self.load_shared_imap()?;
        if let Some(found) = map.get(address) {
            return Ok(found.clone());
        }
        // 32 url-safe bytes — enough entropy for a machine credential that
        // never crosses a human's screen.
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw)
            .map_err(|e| StoreError::Backend(format!("credential entropy: {e}")))?;
        let password: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        map.insert(address.to_owned(), password.clone());
        let bytes = rmp_serde::to_vec(&map).map_err(|e| StoreError::Codec(e.to_string()))?;
        let reply = self
            .inner
            .execute(&Command::Kv {
                namespace: "ayane".to_owned(),
                op: KvOp::Set {
                    key: Value::Text(SHARED_IMAP_KEY.to_owned()),
                    value: Value::Bytes(bytes),
                },
            })
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        match reply {
            Reply::Unit => Ok(password),
            other => Err(StoreError::Backend(format!(
                "unexpected reply for Set: {other:?}"
            ))),
        }
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
                    admin: false,
                }],
                aliases: Vec::new(),
                shared: Vec::new(),
                policy: Policy::default(),
                audit: Default::default(),
                mcp: Default::default(),
            },
            password_hashes: hashes,
            external_identities: Vec::new(),
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

    /// A link row for the identity tests.
    fn link(subject: &str, address: &str) -> ExternalLink {
        ExternalLink {
            provider: "example-idp".to_owned(),
            issuer: None,
            subject: subject.to_owned(),
            address: Address::parse(address).expect("address"),
            created_at: Utc::now(),
            last_login_at: None,
        }
    }

    #[test]
    fn a_snapshot_written_before_links_existed_still_loads() {
        // The field is absent on every snapshot the store wrote before
        // federated sign-in: it must read as "no links", never as a codec
        // error that would take the whole control plane down on upgrade.
        let path = temp_path("legacy").join("state.redb");
        let store = RedbStateStore::open(&path).expect("open");
        // The shape the store wrote before the field existed: the two
        // fields it had, encoded the same way.
        #[derive(serde::Serialize)]
        struct Legacy<'a> {
            desired: &'a DesiredState,
            password_hashes: &'a HashMap<String, String>,
        }
        let current = sample();
        let bytes = rmp_serde::to_vec(&Legacy {
            desired: &current.desired,
            password_hashes: &current.password_hashes,
        })
        .expect("msgpack");
        let reply = store
            .inner
            .execute(&Command::Kv {
                namespace: "ayane".to_owned(),
                op: KvOp::Set {
                    key: Value::Text(STATE_KEY.to_owned()),
                    value: Value::Bytes(bytes),
                },
            })
            .expect("set");
        assert!(matches!(reply, Reply::Unit));
        let loaded = store.load().expect("legacy snapshot loads");
        assert!(loaded.external_identities.is_empty());
        assert_eq!(loaded.desired.accounts.len(), 1);
    }

    #[test]
    fn links_roundtrip_through_the_snapshot() {
        let path = temp_path("links").join("state.redb");
        let store = RedbStateStore::open(&path).expect("open");
        let mut state = sample();
        state
            .external_identities
            .push(link("sub-1", "alice@example.test"));
        store.save(&state).expect("save");
        let loaded = store.load().expect("load");
        assert_eq!(loaded.external_identities.len(), 1);
        assert_eq!(loaded.external_identities[0].subject, "sub-1");
        assert_eq!(
            loaded.external_identities[0].address.to_string(),
            "alice@example.test"
        );
    }

    #[test]
    fn a_rejected_edit_leaves_the_stored_snapshot_untouched() {
        let path = temp_path("rejected").join("state.redb");
        let store = RedbStateStore::open(&path).expect("open");
        store.save(&sample()).expect("save");
        let refused = store.update(&mut |state| {
            state
                .external_identities
                .push(link("sub-1", "alice@example.test"));
            Err(StoreError::Rejected("identity taken".to_owned()))
        });
        assert!(matches!(refused, Err(StoreError::Rejected(_))));
        assert!(store.load().expect("load").external_identities.is_empty());
        // The lock is released after a rejected edit: the next one runs.
        store
            .update(&mut |state| {
                state
                    .external_identities
                    .push(link("sub-1", "alice@example.test"));
                Ok(())
            })
            .expect("second edit");
        assert_eq!(store.load().expect("load").external_identities.len(), 1);
    }

    #[test]
    fn concurrent_edits_never_lose_one_another() {
        // MUT:locked-read-modify-write — every locked edit sees the result
        // of the edits before it; an unlocked load→save here would drop
        // pushes and leave fewer rows than threads.
        let path = temp_path("concurrent").join("state.redb");
        let store = std::sync::Arc::new(RedbStateStore::open(&path).expect("open"));
        store.save(&sample()).expect("save");
        let threads: Vec<_> = (0..16)
            .map(|index| {
                let store = store.clone();
                std::thread::spawn(move || {
                    store
                        .update(&mut |state| {
                            state
                                .external_identities
                                .push(link(&format!("sub-{index}"), "alice@example.test"));
                            Ok(())
                        })
                        .expect("edit");
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("thread");
        }
        assert_eq!(store.load().expect("load").external_identities.len(), 16);
    }

    #[test]
    fn no_account_has_a_cached_credential_yet() {
        // The forwarding-node account kind does not exist yet; until it
        // does, every provider sign-in goes through the mailbox password.
        let state = sample();
        assert!(state
            .cached_credential(&Address::parse("alice@example.test").expect("address"))
            .is_none());
    }

    #[test]
    fn templates_roundtrip_per_owner() {
        let path = temp_path("templates").join("state.redb");
        let store = RedbStateStore::open(&path).expect("open");
        store
            .save_template(&Template {
                id: "t1".to_owned(),
                owner: "alice@example.test".to_owned(),
                name: "报价".to_owned(),
                subject: "Re: quote".to_owned(),
                body: "hello".to_owned(),
            })
            .expect("save");
        store
            .save_template(&Template {
                id: "t2".to_owned(),
                owner: "bob@example.test".to_owned(),
                name: "Bob's".to_owned(),
                subject: "s".to_owned(),
                body: "b".to_owned(),
            })
            .expect("save");

        let alice = store.list_templates("alice@example.test").expect("list");
        assert_eq!(alice.len(), 1);
        assert_eq!(alice[0].name, "报价");

        // An id never crosses owners.
        let stolen = store.save_template(&Template {
            id: "t2".to_owned(),
            owner: "alice@example.test".to_owned(),
            name: "hijack".to_owned(),
            subject: "".to_owned(),
            body: "".to_owned(),
        });
        assert!(stolen.is_err());

        store
            .delete_template("alice@example.test", "t1")
            .expect("delete");
        assert!(store
            .list_templates("alice@example.test")
            .expect("list")
            .is_empty());
        // Bob's template survives Alice's delete.
        assert_eq!(
            store
                .list_templates("bob@example.test")
                .expect("list")
                .len(),
            1
        );
    }
}
