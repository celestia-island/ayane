# Dovecot image: IMAP + LMTP + auth backend for Postfix.
ARG DEBIAN_IMAGE=debian:bookworm-slim
FROM ${DEBIAN_IMAGE}

RUN sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources \
 && apt-get update \
 && apt-get install -y --no-install-recommends dovecot-core dovecot-imapd dovecot-lmtpd \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 5000 vmail \
 && useradd -u 5000 -g 5000 -d /var/mail/vhosts -s /usr/sbin/nologin vmail \
 && mkdir -p /var/mail/vhosts \
 && chown -R vmail:vmail /var/mail/vhosts

COPY dovecot.conf /etc/dovecot/dovecot.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 143 24 12345
ENTRYPOINT ["/entrypoint.sh"]