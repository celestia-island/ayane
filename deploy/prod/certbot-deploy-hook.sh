#!/bin/sh
# certbot deploy hook: reload the mail daemons after certificate renewal
# (certbot rewrites the live/ symlinks; postfix and dovecot hold the old
# certificate in memory until reloaded).
set -e
cd /opt/ayane/deploy/prod
docker compose exec -T postfix postfix reload || true
docker compose exec -T dovecot sh -c 'cp /run/ayane/passwd /etc/dovecot/passwd && chown root:dovecot /etc/dovecot/passwd && chmod 640 /etc/dovecot/passwd && doveadm reload' || true