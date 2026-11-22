#!/usr/bin/python3
"""certbot deploy hook: reload the mail daemons after certificate renewal.

certbot rewrites the live/ symlinks on renewal; postfix and dovecot keep the
old certificate in memory until reloaded. Installed as
/etc/letsencrypt/renewal-hooks/deploy/ on the rig host.

Failures are reported but never raise: a renewal hook that aborts leaves the
certificate switched but daemons stale, which is strictly worse than a
warning line in the hook output.
"""

import subprocess
import sys

COMPOSE = ["docker", "compose", "-f", "/opt/ayane/deploy/prod/docker-compose.yml"]
RELOADS = (
    ("postfix", COMPOSE + ["exec", "-T", "postfix", "python3", "/entrypoint.py", "reload"]),
    ("dovecot", COMPOSE + ["exec", "-T", "dovecot", "python3", "/entrypoint.py", "reload"]),
)


def main() -> int:
    failed = False
    for service, command in RELOADS:
        result = subprocess.run(command, capture_output=True, text=True)
        state = "ok" if result.returncode == 0 else "FAILED"
        print(f"{service}: {state} {result.stdout.strip()}{result.stderr.strip()}")
        failed = failed or result.returncode != 0
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())