#!/usr/bin/env python3
"""Build the deployment binary: a fully static musl `ayane`, and prove it.

Why this exists
---------------
The 2026-11-27 production cutover was rolled back because the binary at
`/opt/ayane/ayane-bin` was (a) linked against GLIBC 2.39 on a host whose glibc
is 2.35 and (b) built from a tree that predates the self-written mail engine —
so `ldd` failed and `AYANE_MAIL_ENABLED` did not appear anywhere in it. Both
faults are build-lane faults, not code faults, and neither is visible from a
file name. This script is the lane that makes them impossible to miss:

  1. builds the **workspace's current HEAD** for `x86_64-unknown-linux-musl`
     (static-pie: no glibc, no dynamic loader — it runs on any Linux x86-64);
  2. refuses to report success unless `ldd` says the artifact is not a dynamic
     executable, the artifact carries the mail engine's own strings, and
     `--version` names the musl target it was built for;
  3. prints the sha256 a deployment records, and (with `--install-to`) copies
     the artifact into place with the same `install -m` shape a unit expects.

The version banner is the third check on purpose: it is read from the binary
itself, so a `cargo build` that silently reused a stale GNU artifact cannot
pass it.

Usage
-----
    python3 deploy/build-musl.py                 # build + verify
    python3 deploy/build-musl.py --install-to /opt/ayane/ayane-bin

Environment (all optional):
    AYANE_MUSL_TARGET   target triple (default x86_64-unknown-linux-musl)
    CARGO_HOME / CARGO_TARGET_DIR  honour cargo's own variables; unset means
                        this script uses the conventional locations
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

TARGET = os.environ.get("AYANE_MUSL_TARGET", "x86_64-unknown-linux-musl")

# The string the engine's own configuration parser looks for. `--version`'s
# banner carries it too, so a binary that does not contain it is either not
# this crate or not this revision.
ENGINE_MARKER = b"AYANE_MAIL_ENABLED"

# What a static-pie musl executable must answer. `ldd` on a static binary
# prints one of these (glibc's script and musl's differ in wording), and
# anything else — including a missing interpreter error — is a dynamic build.
STATIC_MARKERS = ("not a dynamic executable", "statically linked")


def rule(title: str) -> None:
    print(f"\n== {title} " + "=" * max(0, 72 - len(title)))


def run(cmd: list[str], *, capture: bool = False) -> subprocess.CompletedProcess:
    print("$ " + " ".join(cmd), flush=True)
    return subprocess.run(
        cmd,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )


def fail(message: str) -> "NoReturn":  # type: ignore[name-defined]  # noqa: F821
    print(f"build-musl: FAILED — {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--install-to", help="copy the verified binary here")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="pass --offline/--locked to cargo (no registry access)",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    os.chdir(root)

    # The revision this binary is says it is. A cutover that ships a binary
    # whose tree is not the tree the operator believes it is has no way back
    # except the rollback; printing the rev costs nothing.
    try:
        rev = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        rev = "unknown"
    rule(f"building {TARGET} from HEAD {rev}")

    cargo = shutil.which("cargo")
    if cargo is None:
        fail("cargo is not on PATH")

    cmd = [cargo, "build", "--release", "--target", TARGET, "-p", "ayane"]
    if args.offline:
        cmd += ["--offline", "--locked"]
    if run(cmd).returncode != 0:
        fail(f"cargo build --release --target {TARGET} -p ayane")

    target_dir = Path(
        os.environ.get("CARGO_TARGET_DIR") or str(root / "target")
    )
    if not target_dir.is_absolute():
        target_dir = root / target_dir
    binary = target_dir / TARGET / "release" / "ayane"
    if not binary.is_file():
        fail(f"cargo reported success but {binary} is missing")

    rule("verifying the artifact")

    ldd = subprocess.run(
        ["ldd", str(binary)], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    ldd_output = ldd.stdout.strip()
    print(f"ldd: {ldd_output}")
    if not any(marker in ldd_output for marker in STATIC_MARKERS):
        fail(
            f"{binary} is dynamically linked (ldd said: {ldd_output!r}); "
            "this lane exists to ship a binary that does not depend on the host's glibc"
        )

    payload = binary.read_bytes()
    if ENGINE_MARKER not in payload:
        fail(
            f"{binary} does not contain {ENGINE_MARKER.decode()}: it was not built from "
            "this tree (the 2026-11-27 cutover's binary was exactly this)"
        )

    version = subprocess.run(
        [str(binary), "--version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    print("--version:\n" + version.stdout.rstrip())
    if version.returncode != 0:
        fail(f"{binary} --version exited {version.returncode}")
    if TARGET not in version.stdout:
        fail(
            f"--version does not name {TARGET}: the artifact did not come from the "
            f"build above (it said: {version.stdout.strip()!r})"
        )

    digest = hashlib.sha256(payload).hexdigest()
    size = len(payload)
    print(f"sha256: {digest}")
    print(f"size:   {size} bytes")

    sidecar = binary.with_name(binary.name + ".sha256")
    sidecar.write_text(f"{digest}  {binary.name}\n")
    print(f"wrote {sidecar}")

    if args.install_to:
        rule(f"installing to {args.install_to}")
        destination = Path(args.install_to)
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Same-directory temp + rename: a half-copied binary that a supervisor
        # picks up is a binary that fails to exec with a reason nobody sees.
        staged = destination.with_name("." + destination.name + ".new")
        shutil.copyfile(binary, staged)
        os.chmod(staged, 0o755)
        os.replace(staged, destination)
        installed = hashlib.sha256(destination.read_bytes()).hexdigest()
        if installed != digest:
            fail(f"{destination} hashes {installed}, not the built {digest}")
        print(f"installed {destination} ({digest})")

    rule("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
