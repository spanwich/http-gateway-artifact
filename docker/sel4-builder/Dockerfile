FROM trustworthysystems/camkes:2025_05_22

# Install Haskell Stack (needed for capDL-tool)
RUN curl -sSL https://get.haskellstack.org/ | sh

# Sync seL4/CAmkES ecosystem
WORKDIR /workspace
RUN repo init -u https://github.com/seL4/camkes-vm-examples-manifest.git \
    && repo sync -j4

# Download mbedTLS v3.6.5 (required by LwipProxy TLS termination)
RUN wget -q https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.6.5.tar.gz \
    && tar xzf v3.6.5.tar.gz \
    && rm v3.6.5.tar.gz

COPY docker/sel4-builder/build.sh /build.sh
RUN chmod +x /build.sh
