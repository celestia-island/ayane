# Postfix image: MTA with virtual delivery handed to Dovecot LMTP and
# filtering delegated to rspamd over the milter protocol.
ARG DEBIAN_IMAGE=debian:bookworm-slim
FROM ${DEBIAN_IMAGE}

RUN sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources \
 && apt-get update \
 && apt-get install -y --no-install-recommends postfix postfix-pcre python3 \
 && rm -rf /var/lib/apt/lists/*

COPY main.cf /etc/postfix/main.cf
COPY master.cf /etc/postfix/master.cf
COPY entrypoint.py /entrypoint.py

EXPOSE 25 587
ENTRYPOINT ["python3", "/entrypoint.py"]