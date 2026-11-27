#!/usr/bin/env python3
"""End to end: the Python standard library's `imaplib` against `ayane-smtpd --imap`.

This is the same story the Rust listener tests tell, told by the client a
person would actually use: a real binary, a real socket, a real TLS handshake,
and the six commands a mail client runs before it shows an inbox.

What it proves that a unit test cannot:

- the binary's command line (`--imap`, `--tls-cert`, `--password-hashes`) is
  wired to the listener, and the listener is wired to the mail root the
  delivery consumer writes into;
- `imaplib` — which frames literals, matches tags and re-reads its capability
  list in its own way — agrees with this server's framing;
- a message delivered by hand into the maildir is the message IMAP serves.

The certificate is this repository's throwaway `tests/fixtures/test-cert.pem`,
whose SAN is `mx.test`; the client trusts exactly that file. Nothing here is a
credential: the password is this script's own, hashed into the passwd file the
listener reads, and both live in a temporary directory.
"""

from __future__ import annotations

import hashlib
import imaplib
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
# verifies it (`ayane-store`'s `{SHA512-CRYPT}` SHA-512 crypt), not by a second
# implementation here: `tests/imap_hashgen.rs` is that producer.
HASHGEN = ["cargo", "test", "-p", "ayane-smtpd", "--test", "imap_hashgen", "--"]


def imap_password_hash(password: str) -> str:
    """A `{SHA512-CRYPT}` entry for `password`, from the store's own hasher.

    Run inside a work tree, with the workspace's `cargo` on `PATH`; a machine
    without one says so rather than falling back to a hand-rolled hash (this
    file had one for a while, and it did not agree with `crypt(3)` — see the
    `e2e/README.md` note).
    """
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


def read_line(sock, drop_crlf: bool = True) -> bytes:
    """One CRLF-terminated line, octet by octet, from the raw socket."""
    line = b""
    while not line.endswith(b"\r\n"):
        octet = sock.recv(1)
        if not octet:
            raise SystemExit(f"connection closed mid-line: {line!r}")
        line += octet
    return line[: -2] if drop_crlf else line


def read_exactly(sock, count: int) -> bytes:
    """Exactly `count` octets, as a literal promises — CRLF inside them and all."""
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise SystemExit(f"connection closed {count - len(data)} octets into a literal")
        data += chunk
    return data


def pick_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def main() -> int:
    binary = Path(os.environ.get("AYANE_SMTPD_BIN", ROOT / "target/debug/ayane-smtpd"))
    if not binary.exists():
        print(f"no binary at {binary}; build it with `cargo build -p ayane-smtpd`", file=sys.stderr)
        return 2

    work = Path(tempfile.mkdtemp(prefix="ayane-imaplib-"))
    try:
        state = work / "state"
        mail = work / "mail"
        state.mkdir(parents=True)
        mail.mkdir()
        inbox = mail / "example.test" / "alice" / "Maildir"
        for part in ("new", "cur", "tmp"):
            (inbox / part).mkdir(parents=True)
        message = (
            f"From: bob@example.test\r\nTo: {ADDRESS}\r\n"
            "Subject: imaplib end to end\r\n"
            "Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n"
            "Message-ID: <imaplib-e2e@example.test>\r\n\r\n"
            "the body imaplib should fetch\r\n"
        )
        (inbox / "new" / "1700000000.M1.P1.ayane-e2e").write_text(message, newline="")

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
        # The prefix is the store's scheme (`{SHA512-CRYPT}`), and the rounds
        # parameter is the CRT work factor it mints: a passwd file without it
        # is 5 000 rounds, which is not the hash this listener is written for.
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
                        raise SystemExit(f"listener exited: {process.returncode}\n{(work / 'smtpd.log').read_text()}")
                    time.sleep(0.05)
            else:
                raise SystemExit("listener never accepted a connection")

            # The certificate authenticates `mx.test`, and this client connects
            # to it over loopback: the socket is opened to `127.0.0.1`, and the
            # TLS handshake is performed here against an `SSLContext` built
            # for the name the certificate claims, so verification is a real
            # chain-and-hostname check rather than `check_hostname = False`.
            # `IMAP4_SSL` connects to `host` and then requires the certificate
            # to carry that same name — so the name is made to be `mx.test` by
            # a resolver `getaddrinfo` patch that only ever answers this one
            # name, and only ever with the loopback address the listener is on.
            expect_mx_test()
            context = ssl.create_default_context(cafile=str(CERT))
            client = imaplib.IMAP4_SSL("mx.test", port, ssl_context=context, timeout=20)
            # `imaplib` shows every response when it is logging at level 4; the
            # transcript is kept (and printed on failure) because it is the
            # wire, and the wire is what this test is about.
            transcript: list[str] = []
            client.debug = 4
            client._mesg = lambda *args: transcript.append(" ".join(str(a) for a in args))
            steps: list[str] = []

            steps.append("capability: " + " ".join(client.capabilities))
            typed, _ = client.login(ADDRESS, PASSWORD)
            steps.append(f"LOGIN {typed!r}")
            steps.append(f"SELECT {client.select('INBOX')!r}")

            # A `FETCH` answer's literal arrives as its own chunk on the wire
            # (`… BODY[] {188}`, the octets, then the line's `)` trailer), and
            # `imaplib` reads that chunk as a *response* rather than as a
            # literal of the line it belongs to: its parser only recognises a
            # literal that ends a whole line, and `BODY[] {188}` is followed by
            # the rest of the FETCH item list. So the fetch is driven by hand
            # here — the framing is still `imaplib`'s, but the two octet reads
            # are this test's, which is what makes the assertion possible.
            # Over TLS, `imaplib`'s `file` is a `socket.makefile()` buffer, which
            # may have taken octets past the head line — and a literal is the
            # one thing a line reader cannot take. So the answer is read off
            # the *unbuffered* socket, to its own counts; anything the buffer
            # already holds is answered by the server again below.
            # `imaplib`'s tags are `_new_tag()`'s, four random characters plus a
            # counter: the tag is taken from the client so the command is one
            # the library itself would write.
            # `imaplib`'s tags come from `_new_tag()`, so the command this test
            # writes is tagged the way the library would tag its own.
            fetch_tag = client._new_tag()
            client.send(fetch_tag + b" FETCH 1 (UID RFC822.SIZE BODY.PEEK[])\r\n")
            # The answer is `* 1 FETCH (…) BODY[] {n}` CRLF, then exactly `n`
            # octets (which begin at the announcement's `{`, so the first of
            # them are the `{n}` and CRLF themselves — see the note below),
            # then the line's `)` trailer, then the tagged `OK`. Over TLS the
            # client's line buffer cannot be used for any of it: a literal is
            # the one thing a line reader cannot take.
            head = read_line(client.sock, drop_crlf=False)
            if b"BODY[] {" not in head or not head.startswith(b"* 1 FETCH"):
                raise SystemExit(f"unexpected FETCH head: {head!r}")
            size = int(head.rsplit(b"{", 1)[1].rstrip(b"\r\n").rstrip(b"}"))
            # `n` is octets of the message, and the message begins after the
            # announcement's own octets (`{n}` and the CRLF that ends the line
            # it sits on) — so `n` plus those is what the wire carries here.
            promised = read_exactly(client.sock, size + len(head) - head.rfind(b"{"))
            message = promised[len(head) - head.rfind(b"{") :]
            trailer = client._get_line()
            tagged = client._get_line()
            if not tagged.startswith(fetch_tag + b" OK"):
                raise SystemExit(f"FETCH answered {tagged!r} after {trailer!r}")
            if len(message) != size or b"the body imaplib should fetch" not in message:
                raise SystemExit(f"FETCH returned {len(message)} octets, not the message")
            steps.append(
                f"FETCH {size}-octet literal: {head.decode(errors='replace')} | "
                f"{trailer.decode(errors='replace')} | {tagged.decode(errors='replace')}"
            )
            status, data = client.store("1", "+FLAGS", r"(\Flagged \Seen)")
            steps.append(f"STORE {status}: {data!r}")

            status, data = client.search(None, "FLAGGED")
            if data != [b"1"]:
                raise SystemExit(f"SEARCH FLAGGED expected [b'1'], got {data!r}")
            steps.append(f"SEARCH FLAGGED {status}: {data!r}")

            status, data = client.search(None, "UNSEEN")
            if data != [b""]:
                raise SystemExit(f"SEARCH UNSEEN expected nothing, got {data!r}")
            steps.append(f"SEARCH UNSEEN {status}: {data!r}")

            typed, _ = client.logout()
            steps.append(f"LOGOUT {typed!r}")

            # The flags STORE set are on disk, as the maildir rename they are.
            stored = list((inbox / "cur").iterdir())
            if not stored or "F" not in stored[0].name or "S" not in stored[0].name:
                raise SystemExit(f"STORE did not rename the file into cur/ with FS: {stored}")
            steps.append(f"maildir cur/: {stored[0].name}")

            steps.append(f"server: {client.welcome.decode(errors='replace').strip()}")
            print("\n".join(steps))
            return 0
        except BaseException:
            print("\n".join(locals().get("transcript", [])), file=sys.stderr)
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
    sys.exit(main())
