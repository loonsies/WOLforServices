FROM golang:1.23-bookworm

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    flex \
    bison \
    wget \
    tar \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Build libpcap v1.10.4 from source
WORKDIR /build-libpcap
RUN wget https://www.tcpdump.org/release/libpcap-1.10.4.tar.gz && \
    tar -xzf libpcap-1.10.4.tar.gz && \
    cd libpcap-1.10.4 && \
    ./configure && \
    make && \
    make install && \
    ldconfig

# Set workspace as the default directory
WORKDIR /workspace
