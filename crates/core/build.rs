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
    // The webmail dist tree is a build-time input of `#[derive(RustEmbed)]` in
    // `src/webui.rs`, and the derive hard-fails when the folder is absent — a
    // `cargo publish` (or a docs.rs build) of the packaged crate runs against a
    // tarball that contains only `crates/core`, so the folder never exists
    // there. Materializing it empty keeps that build green, and an empty
    // embedded set is exactly the "front end was never built" state the serving
    // layer already handles (`index_shell()` returns `None`, the error landing
    // disables itself). A real local `packages/webui/dist` is left untouched.
    let dist = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packages/webui/dist");
    let _ = std::fs::create_dir_all(dist);
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=AYANE_BUILD_TARGET={target}");
    println!("cargo:rerun-if-changed=build.rs");
}
