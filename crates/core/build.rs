//! Records the build's target triple for `--version`.
//!
//! `--version` has to say which build a host is running, and the one fact that
//! matters most is the triple it was compiled for: a binary built for a newer
//! glibc than the host has, or one that is not the target the deployment
//! script thinks it copied, is a cutover that fails an hour later. Rust has no
//! `env!`-style access to the triple, so the build script records it and the
//! program reads it back with `env!("AYANE_BUILD_TARGET")`.
//!
//! The mail engine's presence is **not** a Cargo feature: `crates/core` depends
//! on `ayane-smtpd` unconditionally, so a build that lacks it is a build from
//! another tree (the 2026-11-27 cutover's binary was one). Reporting it as
//! linked is therefore a statement about this manifest, and the deployment's
//! check is `--version` plus the process actually binding its listeners.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=AYANE_BUILD_TARGET={target}");
    println!("cargo:rerun-if-changed=build.rs");
}
