//! Render → diff → write → reload.
//!
//! The apply loop is the only writer of engine configuration. It renders the
//! whole desired state into memory, byte-compares each file against what is on
//! disk, rewrites only what changed (with strict permissions on secrets), then
//! asks the driver to reload the daemons. Rendering twice from one state is
//! byte-identical, so an unchanged state rewrites nothing.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use ayane_engine::{
    dovecot_passwd, postfix_sender_denylist, postfix_virtual_aliases, postfix_virtual_domains,
    postfix_virtual_mailboxes, rspamd_local_domains,
};
use ayane_proto::DesiredState;
use ayane_store::StoredState;

use crate::driver::EngineDriver;

/// Why an apply failed before any reload was attempted.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// The stored state does not validate.
    #[error("state does not validate: {0}")]
    Invalid(String),
    /// An account has no password hash (cannot render its passwd line).
    #[error("account `{0}` has no password hash")]
    MissingHash(String),
    /// The filesystem refused a write.
    #[error("io: {0}")]
    Io(String),
    /// The engine could not be reloaded at all (missing compose file).
    #[error("reload: {0}")]
    Reload(String),
}

/// One rendered file: relative path under the state dir, contents, unix mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedFile {
    /// Path relative to the state dir, e.g. `config/postfix/virtual_domains`.
    pub rel_path: String,
    /// Full file contents (deterministic for a given state).
    pub contents: String,
    /// Unix permission bits to enforce on write.
    pub mode: u32,
}

/// What happened to one file during apply.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FileOutcome {
    /// Path relative to the state dir.
    pub path: String,
    /// Whether the on-disk content changed.
    pub changed: bool,
}

/// The full apply report.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ApplyReport {
    /// Per-file outcomes (every rendered file, changed or not).
    pub files: Vec<FileOutcome>,
    /// Per-service reload outcomes; empty when the engine was absent.
    pub reloaded: Vec<crate::driver::ServiceReload>,
    /// Non-fatal notes (e.g. engine not running yet).
    pub warnings: Vec<String>,
}

/// Render every engine file from one stored state.
///
/// # Errors
///
/// Returns [`ApplyError::MissingHash`] when an enabled account has no password
/// hash (the API forbids this, so this guards hand-edited stores).
pub fn render_all(stored: &StoredState) -> Result<Vec<RenderedFile>, ApplyError> {
    let state: &DesiredState = &stored.desired;
    state
        .validate()
        .map_err(|e| ApplyError::Invalid(e.to_string()))?;

    let mut passwd_entries: Vec<(&ayane_proto::Address, &str)> = Vec::new();
    for account in &state.accounts {
        let hash = stored
            .password_hash(&account.address)
            .ok_or_else(|| ApplyError::MissingHash(account.address.to_string()))?;
        passwd_entries.push((&account.address, hash));
    }

    Ok(vec![
        RenderedFile {
            rel_path: "config/postfix/virtual_domains".to_owned(),
            contents: postfix_virtual_domains(state),
            mode: 0o644,
        },
        RenderedFile {
            rel_path: "config/postfix/virtual_mailboxes".to_owned(),
            contents: postfix_virtual_mailboxes(state),
            mode: 0o644,
        },
        RenderedFile {
            rel_path: "config/postfix/virtual_aliases".to_owned(),
            contents: postfix_virtual_aliases(state),
            mode: 0o644,
        },
        RenderedFile {
            rel_path: "config/postfix/sender_denylist".to_owned(),
            contents: postfix_sender_denylist(state),
            mode: 0o644,
        },
        RenderedFile {
            rel_path: "config/dovecot/passwd".to_owned(),
            contents: dovecot_passwd(passwd_entries),
            mode: 0o600,
        },
        RenderedFile {
            rel_path: "config/rspamd/options.inc".to_owned(),
            contents: rspamd_local_domains(state),
            mode: 0o644,
        },
    ])
}

/// Write changed files under `state_dir` and reload the engine.
///
/// # Errors
///
/// Returns [`ApplyError`] when rendering, validation or the filesystem fails.
/// Reload problems are reported in the report (and as warnings), not as errors:
/// a cold engine that has not been started yet must not fail the first apply.
pub async fn apply(
    state_dir: &std::path::Path,
    stored: &StoredState,
    driver: std::sync::Arc<dyn EngineDriver>,
) -> Result<ApplyReport, ApplyError> {
    let rendered = render_all(stored)?;
    let mut files = Vec::with_capacity(rendered.len());
    let mut changed_any = false;

    for file in &rendered {
        let target: PathBuf = state_dir.join(&file.rel_path);
        let existing = tokio::fs::read(&target).await.ok();
        let same = existing
            .as_ref()
            .is_some_and(|bytes| bytes == file.contents.as_bytes());
        if !same {
            if let Some(parent) = target.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| ApplyError::Io(format!("{}: {e}", parent.display())))?;
            }
            tokio::fs::write(&target, &file.contents)
                .await
                .map_err(|e| ApplyError::Io(format!("{}: {e}", target.display())))?;
            let perms = std::fs::Permissions::from_mode(file.mode);
            tokio::fs::set_permissions(&target, perms)
                .await
                .map_err(|e| ApplyError::Io(format!("{}: {e}", target.display())))?;
            changed_any = true;
        }
        files.push(FileOutcome {
            path: file.rel_path.clone(),
            changed: !same,
        });
    }

    let _ = changed_any;
    let mut warnings = Vec::new();
    let reloaded = match tokio::task::spawn_blocking(move || driver.reload()).await {
        Ok(Ok(list)) => list,
        Ok(Err(e)) => {
            warnings.push(e);
            Vec::new()
        }
        Err(e) => {
            warnings.push(format!("reload task: {e}"));
            Vec::new()
        }
    };

    Ok(ApplyReport {
        files,
        reloaded,
        warnings,
    })
}
