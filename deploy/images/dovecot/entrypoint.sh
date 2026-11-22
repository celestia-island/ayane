#!/bin/sh
# Materialise the operator-owned (0600) passwd mount as a dovecot-readable
# copy inside the container, then run the daemon in the foreground.
set -e
mkdir -p /var/mail/vhosts
chown 5000:5000 /var/mail/vhosts
if [ -f /run/ayane/dovecot.conf ]; then cp /run/ayane/dovecot.conf /etc/dovecot/dovecot.conf; fi
cp /run/ayane/passwd /etc/dovecot/passwd
chown root:dovecot /etc/dovecot/passwd
chmod 640 /etc/dovecot/passwd
exec /usr/sbin/dovecot -F
