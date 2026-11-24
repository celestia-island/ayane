//! How rendered configuration reaches the engine.
//!
//! Rendering is pure; *applying* it is an I/O concern: files land under the
//! state directory (mounted into the engine containers) and the daemons are
//! told to reload. The compose driver shells out to `docker compose exec`,
//! which is the dev/single-host shape; a production driver would speak to
//! systemd units instead. The trait keeps that swap local.

use std::process::Command;

/// Result of one daemon reload.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ServiceReload {
    /// Which engine service this is about.
    pub service: &'static str,
    /// Whether the reload command exited 0.
    pub ok: bool,
    /// Captured stdout/stderr (trimmed) for the report.
    pub detail: String,
}

/// Push a rendered configuration into the running engine.
pub trait EngineDriver: Send + Sync {
    /// Reload every daemon that consumes rendered configuration.
    ///
    /// # Errors
    ///
    /// Implementations report per-service outcomes instead of failing whole;
    /// this returns `Err` only when the reload could not even be attempted
    /// (e.g. the compose file is missing).
    fn reload(&self) -> Result<Vec<ServiceReload>, String>;

    /// Recent postfix log lines (traffic statistics read these: inbound
    /// `connect from` peers and outbound `relay=`/`status=` deliveries).
    /// Empty when the engine exposes no logs.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the logs could not even be attempted.
    fn postfix_logs(&self, since: &str) -> Result<Vec<String>, String>;
}

/// Reload recipe per service: command run inside its container.
const RELOADS: &[(&str, Option<&[&str]>)] = &[
    (
        "postfix",
        Some(&[
            "sh",
            "-c",
            "cp /run/ayane/main.cf /etc/postfix/main.cf 2>/dev/null; cp /run/ayane/master.cf \
             /etc/postfix/master.cf 2>/dev/null; postfix reload",
        ]),
    ),
    (
        "dovecot",
        Some(&[
            "sh",
            "-c",
            "cp /run/ayane/passwd /etc/dovecot/passwd && chown root:dovecot              /etc/dovecot/passwd && chmod 640 /etc/dovecot/passwd && doveadm reload",
        ]),
    ),
    ("rspamd", None),
];

/// Dev/single-host driver: `docker compose exec` into the engine containers.
pub struct ComposeDriver {
    /// Compose file defining the engine.
    pub compose_file: std::path::PathBuf,
}

impl EngineDriver for ComposeDriver {
    fn reload(&self) -> Result<Vec<ServiceReload>, String> {
        if !self.compose_file.is_file() {
            return Err(format!(
                "compose file not found: {} (start the engine first)",
                self.compose_file.display()
            ));
        }
        let mut out = Vec::new();
        for (service, args) in RELOADS {
            let output = match args {
                Some(args) => Command::new("docker")
                    .arg("compose")
                    .arg("-f")
                    .arg(&self.compose_file)
                    .arg("exec")
                    .arg("-T")
                    .arg(service)
                    .args(*args)
                    .output(),
                None => Command::new("docker")
                    .arg("compose")
                    .arg("-f")
                    .arg(&self.compose_file)
                    .arg("restart")
                    .arg(service)
                    .output(),
            };
            let (ok, detail) = match output {
                Ok(output) => {
                    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
                    let err = String::from_utf8_lossy(&output.stderr).into_owned();
                    if !err.trim().is_empty() {
                        if !text.trim().is_empty() {
                            text.push(' ');
                        }
                        text.push_str(&err);
                    }
                    (output.status.success(), text.trim().to_owned())
                }
                Err(e) => (false, format!("spawn docker: {e}")),
            };
            out.push(ServiceReload {
                service,
                ok,
                detail,
            });
        }
        Ok(out)
    }

    fn postfix_logs(&self, since: &str) -> Result<Vec<String>, String> {
        if !self.compose_file.is_file() {
            return Err(format!(
                "compose file not found: {} (start the engine first)",
                self.compose_file.display()
            ));
        }
        let output = Command::new("docker")
            .arg("compose")
            .arg("-f")
            .arg(&self.compose_file)
            .arg("logs")
            .arg("--no-color")
            .arg("--no-log-prefix")
            .arg("--since")
            .arg(since)
            .arg("postfix")
            .output()
            .map_err(|e| format!("spawn docker: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "docker compose logs failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_owned)
            .collect())
    }
}

/// Test double: records reload invocations, never shells out.
pub struct RecordingDriver {
    /// Path whose existence controls whether reloads "succeed".
    pub compose_file: std::path::PathBuf,
    calls: std::sync::Mutex<Vec<&'static str>>,
    /// Log lines `postfix_logs` replays (empty = none recorded).
    pub log_lines: std::sync::Mutex<Vec<String>>,
}

impl RecordingDriver {
    /// Create a driver that records calls and succeeds when `compose_file`
    /// exists (mirrors [`ComposeDriver`]'s missing-file error).
    #[must_use]
    pub fn new(compose_file: std::path::PathBuf) -> Self {
        Self {
            compose_file,
            calls: std::sync::Mutex::new(Vec::new()),
            log_lines: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// The services reload was invoked for, in order.
    pub fn called(&self) -> Vec<&'static str> {
        self.calls.lock().expect("calls mutex").clone()
    }
}

impl EngineDriver for RecordingDriver {
    fn reload(&self) -> Result<Vec<ServiceReload>, String> {
        if !self.compose_file.is_file() {
            return Err("compose file not found".to_owned());
        }
        let mut calls = self.calls.lock().expect("calls mutex");
        Ok(RELOADS
            .iter()
            .map(|(service, _)| {
                calls.push(service);
                ServiceReload {
                    service,
                    ok: true,
                    detail: "recorded".to_owned(),
                }
            })
            .collect())
    }

    fn postfix_logs(&self, _since: &str) -> Result<Vec<String>, String> {
        if !self.compose_file.is_file() {
            return Err("compose file not found".to_owned());
        }
        Ok(self.log_lines.lock().expect("log mutex").clone())
    }
}
