#!/bin/sh
# Materialise the staged config copies (single-file mounts under /run/ayane)
# into the container's /etc/postfix, then run the daemon in the foreground.
# Staging avoids both problems of direct config mounts: a directory mount
# shadows the package's postfix-files (integrity check fails, crash loop),
# and a single-file mount pins the inode so host-side edits never reach a
# running container.
set -e
# Staged (prod) when present; otherwise keep the baked dev configs.
if [ -f /run/ayane/main.cf ]; then cp /run/ayane/main.cf /etc/postfix/main.cf; fi
if [ -f /run/ayane/master.cf ]; then cp /run/ayane/master.cf /etc/postfix/master.cf; fi
exec /usr/sbin/postfix start-fg