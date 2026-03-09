FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-system-x86 curl jq netcat-openbsd python3 \
    && rm -rf /var/lib/apt/lists/*

COPY start-gateway-slirp.sh /usr/local/bin/
COPY run-tests.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh

EXPOSE 8443
