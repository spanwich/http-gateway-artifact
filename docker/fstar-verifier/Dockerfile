FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev make wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download EverParse binary release (includes F* + KreMLin)
ARG EVERPARSE_VERSION=v2025.10.06
RUN wget -q "https://github.com/project-everest/everparse/releases/download/${EVERPARSE_VERSION}/everparse_${EVERPARSE_VERSION}_Linux_x86_64.tar.gz" \
    -O /tmp/everparse.tar.gz \
    && mkdir -p /opt/everparse \
    && tar xzf /tmp/everparse.tar.gz -C /opt/everparse --strip-components=1 \
    && rm /tmp/everparse.tar.gz

ENV EVERPARSE_HOME=/opt/everparse

COPY docker/fstar-verifier/verify.sh /verify.sh
RUN chmod +x /verify.sh

RUN mkdir -p /work
WORKDIR /workspace
