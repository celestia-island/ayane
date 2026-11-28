#!/usr/bin/env python3
"""End to end: CONDSTORE + QRESYNC + UIDPLUS against `ayane-smtpd --imap`.

The same story the Rust listener tests tell (`crates/smtpd/tests/`
`imap_condstore.rs`), told over a real wire by a client that behaves the way
Thunderbird does: raw send, raw line reads, no library beyond the standard
one — `imaplib` cannot express `ENABLE QRESYNC`, a `SELECT (QRESYNC …)`
parameter, `CHANGEDSINCE`/`VANISHED` or `UNCHANGEDSINCE`, and this test is
about the exact bytes those answers are spelled with.

Two phases:

1. **condstore** — connection A selects with `(CONDSTORE)`, connection B
   changes a flag behind its back, A's `NOOP` reports the change as a FETCH
   with `UID` and `MODSEQ`, and A's stale `UNCHANGEDSINCE` lands in
   `[MODIFIED]`. The `ayane-modseq` sidecar on disk is asserted too: the `h`
   watermark grew with every recorded change.
2. **qresync** — A enables QRESYNC, expunges, and hears `* VANISHED` (no
   `(EARLIER)`); a fresh connection replays the removal as `* VANISHED
   (EARLIER)` — strictly before the FETCH lines, intersected with the UIDs it
   claims to hold — and `CLOSE` answers a bare OK (RFC 7162 §3.2.8, errata
   1808).

Nothing here is a credential: the password is this script's own, hashed into
the passwd file the listener reads, and both live in a temporary directory.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CERT = ROOT / "crates/smtpd/tests/fixtures/test-cert.pem"
KEY = ROOT / "crates/smtpd/tests/fixtures/test-key.pem"
ADDRESS = "alice@example.test"
PASSWORD = "correct horse battery staple"

# The hash the listener checks is produced by the crate that mints and
# verifies it (`ayane-store`'s `{SHA512-CRYPT}` SHA-512 crypt), not by a
# second implementation here: `tests/imap_hashgen.rs` is that producer.
HASHGEN = ["cargo", "test", "-p", "ayane-smtpd", "--test", "imap_hashgen", "--"]


def imap_password_hash(password: str) -> str:
    cargo = shutil.which("cargo")
    if not cargo:
        raise SystemExit(
            "no `cargo` on PATH: the passwd fixture is written by the store's "
            "own hasher (`cargo test -p ayane-smtpd --test imap_hashgen`)"
        )
    out = subprocess.run(
        HASHGEN + [password],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    for line in reversed(out.splitlines()):
        if line.startswith("{SHA512-CRYPT}"):
            return line.strip()
    raise SystemExit(f"the hash generator printed no hash:\n{out}")


def expect_mx_test() -> None:
    """Make `mx.test` resolve to loopback, for this process only."""
    real = socket.getaddrinfo

    def patched(host, port, family=0, type=0, proto=0, flags=0):
        if host in {"mx.test", b"mx.test"}:
            return real("127.0.0.1", port, family, type, proto, flags)
        return real(host, port, family, type, proto, flags)

    socket.getaddrinfo = patched


def read_line(sock) -> bytes:
    """One CRLF-terminated line, octet by octet, from the raw socket."""
    line = b""
    while not line.endswith(b"\r\n"):
        octet = sock.recv(1)
        if not octet:
            raise SystemExit(f"connection closed mid-line: {line!r}")
        line += octet
    return line[: -2]


def pick_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Client:
    """A raw TLS IMAP client: send a line, read replies to its tag."""

    def __init__(self, port: int) -> None:
        context = ssl.create_default_context(cafile=str(CERT))
        raw = socket.create_connection(("127.0.0.1", port), timeout=20)
        self.sock = context.wrap_socket(raw, server_hostname="mx.test")
        self.counter = 0
        self.greeting = read_line(self.sock)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def send(self, line: str) -> str:
        self.counter += 1
        self.tag = f"t{self.counter:02d}"
        self.sock.sendall(f"{self.tag} {line}\r\n".encode())
        return self.tag

    def reply_lines(self, tag: str) -> list[str]:
        lines = []
        prefix = f"{tag} ".encode()
        while True:
            line = read_line(self.sock)
            text = line.decode(errors="replace")
            lines.append(text)
            if text.startswith(f"{tag.decode() if isinstance(tag, bytes) else tag} "):
                return lines
            _ = prefix

    def say(self, line: str) -> list[str]:
        tag = self.send(line)
        return self.reply_lines(tag)

    def tagged(self, lines: list[str]) -> str:
        return lines[-1]

    def login(self) -> None:
        reply = self.say(f"LOGIN {ADDRESS} \"{PASSWORD}\"")
        assert f"{self.tag} OK" in reply[-1], f"LOGIN: {reply}"

    def highestmodseq(self, lines: list[str]) -> int:
        for line in lines:
            if "[HIGHESTMODSEQ " in line:
                return int(line.split("[HIGHESTMODSEQ ")[1].split("]")[0])
            if " HIGHESTMODSEQ " in line and line.startswith("* STATUS"):
                return int(line.split(" HIGHESTMODSEQ ")[1].rstrip(")"))
        raise SystemExit(f"no HIGHESTMODSEQ in {lines!r}")

    def uidvalidity(self, lines: list[str]) -> int:
        for line in lines:
            if "[UIDVALIDITY " in line:
                return int(line.split("[UIDVALIDITY ")[1].split("]")[0])
        raise SystemExit(f"no UIDVALIDITY in {lines!r}")


def untagged_fetch(lines: list[str]) -> list[str]:
    """The `* n FETCH` lines of a reply (the tagged OK also says FETCH)."""
    return [line for line in lines if line.startswith("* ") and "FETCH (" in line]


def watermark_of_modseq(line: str) -> int:
    return int(line.split("MODSEQ (")[1].split(")")[0])


def main() -> int:
    binary = Path(os.environ.get("AYANE_SMTPD_BIN", "target/debug/ayane-smtpd"))
    if not binary.is_absolute():
        binary = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")) / "debug" / "ayane-smtpd"
    if not binary.exists():
        print(f"no binary at {binary}; build it with `cargo build -p ayane-smtpd`", file=sys.stderr)
        return 2

    work = Path(tempfile.mkdtemp(prefix="ayane-condstore-"))
    try:
        state = work / "state"
        mail = work / "mail"
        state.mkdir(parents=True)
        mail.mkdir()
        inbox = mail / "example.test" / "alice" / "Maildir"
        for part in ("new", "cur", "tmp"):
            (inbox / part).mkdir(parents=True)
        for seq, subject in ((1, "first"), (2, "second"), (3, "third")):
            name = f"17000000{seq:02d}.M1.P1.ayane-e2e"
            message = (
                f"From: bob@example.test\r\nTo: {ADDRESS}\r\nSubject: {subject}\r\n"
                "Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n"
                f"Message-ID: <{name}>\r\n\r\nbody of {subject}\r\n"
            )
            (inbox / "new" / name).write_text(message, newline="")

        desired = {
            "domains": [{"name": "example.test", "catch_all": None, "enabled": True}],
            "accounts": [
                {
                    "id": "11111111-1111-1111-1111-111111111111",
                    "address": ADDRESS,
                    "display_name": "Alice",
                    "quota_bytes": 0,
                    "admin": False,
                }
            ],
            "aliases": [],
            "shared": [],
            "policy": {"default_action": "reject", "allowlist": [], "denylist": []},
        }
        (state / "desired-state.json").write_text(json.dumps(desired))
        hashed = imap_password_hash(PASSWORD)
        (work / "passwd").write_text(f"{ADDRESS}:{hashed}\n")

        port = pick_port()
        log = (work / "smtpd.log").open("w")
        process = subprocess.Popen(
            [
                str(binary),
                "--imap",
                "--listen",
                f"127.0.0.1:{port}",
                "--mail-root",
                str(mail),
                "--state",
                str(state / "desired-state.json"),
                "--hostname",
                "mx.test",
                "--tls-cert",
                str(CERT),
                "--tls-key",
                str(KEY),
                "--password-hashes",
                str(work / "passwd"),
                "--imap-tls",
            ],
            stdout=log,
            stderr=log,
        )
        try:
            deadline = time.time() + 20
            while time.time() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1):
                        break
                except OSError:
                    if process.poll() is not None:
                        raise SystemExit(
                            f"listener exited: {process.returncode}\n"
                            f"{(work / 'smtpd.log').read_text()}"
                        )
                    time.sleep(0.05)
            else:
                raise SystemExit("listener never accepted a connection")

            expect_mx_test()
            steps: list[str] = []

            # ── phase one: condstore ──────────────────────────────────────
            a = Client(port)
            a.login()
            lines = a.say("SELECT INBOX (CONDSTORE)")
            assert f"{a.tag} OK" in lines[-1], f"SELECT: {lines}"
            highest = a.highestmodseq(lines)
            assert highest >= 2, f"the scan assigned values: {lines}"
            validity = a.uidvalidity(lines)
            steps.append(f"condstore: SELECT (CONDSTORE) → HIGHESTMODSEQ {highest}")

            # B flips a flag behind A's back; A's NOOP must report it with
            # UID and MODSEQ (RFC 7162 §3.2.4).
            b = Client(port)
            b.login()
            lines = b.say("SELECT INBOX (CONDSTORE)")
            assert f"{b.tag} OK" in lines[-1], f"B SELECT: {lines}"
            lines = b.say("STORE 1 +FLAGS (\\Flagged)")
            fetch = untagged_fetch(lines)
            assert fetch and "MODSEQ (" in fetch[0], f"B STORE: {lines}"

            lines = a.say("NOOP")
            fetch = untagged_fetch(lines)
            assert fetch, f"A's NOOP must report the flag change: {lines}"
            assert "UID 1" in fetch[0] and "\\Flagged" in fetch[0], f"{fetch[0]}"
            changed = watermark_of_modseq(fetch[0])
            assert changed > highest, f"the change is above the old watermark: {fetch[0]}"
            steps.append(f"condstore: NOOP heard FETCH {fetch[0].strip()}")

            # A stale UNCHANGEDSINCE lands in [MODIFIED] (RFC 7162 §3.1.3).
            lines = a.say(f"STORE 1 (UNCHANGEDSINCE {highest}) +FLAGS (\\Seen)")
            assert "[MODIFIED 1]" in lines[-1], f"stale STORE: {lines}"
            assert not untagged_fetch(lines), f"nothing executed: {lines}"
            # Equality passes.
            lines = a.say(f"STORE 1 (UNCHANGEDSINCE {changed}) +FLAGS (\\Seen)")
            assert f"{a.tag} OK" in lines[-1] and "MODIFIED" not in lines[-1], f"{lines}"
            fetch = untagged_fetch(lines)
            assert fetch and "\\Seen" in fetch[0] and "MODSEQ (" in fetch[0], f"{fetch}"
            steps.append("condstore: UNCHANGEDSINCE stale → [MODIFIED 1], equal → OK")

            # The sidecar on disk grew with every recorded change.
            sidecar = (inbox / "ayane-modseq").read_text()
            h_lines = [line for line in sidecar.splitlines() if line.startswith("h ")]
            assert h_lines and int(h_lines[0].split()[1]) >= changed, f"{sidecar!r}"
            steps.append(f"condstore: sidecar {h_lines[0]!r}")
            a.close()
            b.close()

            # ── phase two: qresync ────────────────────────────────────────
            q = Client(port)
            q.login()
            lines = q.say("ENABLE QRESYNC")
            enabled = [line for line in lines if line.startswith("* ENABLED")]
            assert enabled == ["* ENABLED QRESYNC"], f"{lines}"
            lines = q.say("SELECT INBOX")
            assert f"{q.tag} OK" in lines[-1], f"{lines}"

            # Expunge uid 2: the QRESYNC session hears VANISHED (no EARLIER)
            # and the tagged OK carries the watermark (RFC 7162 §3.2.7).
            lines = q.say("STORE 2 +FLAGS (\\Deleted)")
            assert f"{q.tag} OK" in lines[-1], f"{lines}"
            lines = q.say("EXPUNGE")
            vanished = [line for line in lines if line.startswith("* VANISHED")]
            assert vanished == ["* VANISHED 2"], f"{lines}"
            assert not [line for line in lines if line.endswith(" EXPUNGE")], f"{lines}"
            assert "[HIGHESTMODSEQ" in lines[-1], f"tagged code: {lines[-1]}"
            steps.append(f"qresync: EXPUNGE heard {vanished[0]!r} + [HIGHESTMODSEQ]")

            # A fresh connection replays the removal from before its snapshot:
            # VANISHED (EARLIER) first, intersected with known-uids.
            r = Client(port)
            r.login()
            lines = r.say("ENABLE QRESYNC")
            assert any(line.startswith("* ENABLED") for line in lines), f"{lines}"
            # A client holding only uid 1 hears nothing about uid 2 …
            lines = r.say(f"SELECT INBOX (QRESYNC ({validity} 1 1:1))")
            assert not [line for line in lines if "VANISHED" in line], f"{lines}"
            assert f"{r.tag} OK" in lines[-1], f"{lines}"
            # … and one holding 1:10 hears exactly uid 2, before the FETCHes.
            lines = r.say(f"SELECT INBOX (QRESYNC ({validity} 1 1:10))")
            vanished_at = [i for i, line in enumerate(lines) if "VANISHED (EARLIER)" in line]
            fetch_at = [i for i, line in enumerate(lines) if "FETCH (" in line]
            assert vanished_at, f"{lines}"
            assert vanished_at[0] < fetch_at[0], f"order: {lines}"
            assert lines[vanished_at[0]] == "* VANISHED (EARLIER) 2", f"{lines}"
            fetches = untagged_fetch(lines)
            assert fetches and all("MODSEQ (" in line for line in fetches), f"{fetches}"
            steps.append(f"qresync: replay {lines[vanished_at[0]]!r} before {len(fetches)} FETCH lines")
            r.close()

            # UID EXPUNGE removes only the intersection (RFC 4315 §2.1).
            lines = q.say("STORE 1 +FLAGS (\\Deleted)")
            assert f"{q.tag} OK" in lines[-1], f"{lines}"
            lines = q.say("UID EXPUNGE 1:2")
            assert f"{q.tag} OK" in lines[-1], f"{lines}"
            lines = q.say("UID FETCH 1:* (UID)")
            assert "UID 3" in "".join(lines) and "UID 1" not in "".join(lines), f"{lines}"

            # CLOSE: bare OK, no detail lines, no code — even under QRESYNC
            # (RFC 3501 §6.4.2; RFC 7162 §3.2.8, errata 1808).
            lines = q.say("UID STORE 3 +FLAGS (\\Deleted)")
            assert f"{q.tag} OK" in lines[-1], f"{lines}"
            lines = q.say("CLOSE")
            assert lines == [f"{q.tag} OK CLOSE completed"], f"CLOSE: {lines}"
            steps.append("qresync: CLOSE answered a bare OK")

            # And the deletion was recorded for the next resync.
            r2 = Client(port)
            r2.login()
            r2.say("ENABLE QRESYNC")
            lines = r2.say(f"SELECT INBOX (QRESYNC ({validity} 1 1:10))")
            vanished = [line for line in lines if "VANISHED (EARLIER)" in line]
            assert vanished == ["* VANISHED (EARLIER) 1:3"], f"{lines}"
            r2.close()
            steps.append("qresync: resync replays the CLOSE deletions as VANISHED (EARLIER) 1:3")

            q.close()
            steps.append(f"greeting: {a.greeting.decode(errors='replace').strip()}")
            print("\n".join(steps))
            return 0
        except BaseException:
            print((work / "smtpd.log").read_text(), file=sys.stderr)
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
            log.close()
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    warnings.simplefilter("ignore", ResourceWarning)
    sys.exit(main())
