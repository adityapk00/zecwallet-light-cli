FROM rust:1.38
LABEL Description="Rust compile env for Linux + Windows (cross)"

RUN apt update
RUN apt install -y build-essential mingw-w64 gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf

RUN rustup target add x86_64-pc-windows-gnu
RUN rustup target add aarch64-unknown-linux-gnu
RUN rustup target add armv7-unknown-linux-gnueabihf

# Append the linker to the cargo config for Windows cross compile
RUN echo "[target.x86_64-pc-windows-gnu]" >> /usr/local/cargo/config && \
    echo "linker = '/usr/bin/x86_64-w64-mingw32-gcc'" >> /usr/local/cargo/config

RUN echo "[target.aarch64-unknown-linux-gnu]" >> /usr/local/cargo/config && \
    echo "linker = '/usr/bin/aarch64-linux-gnu-gcc'" >> /usr/local/cargo/config

RUN echo "[target.armv7-unknown-linux-gnueabihf]" >> /usr/local/cargo/config && \
    echo "linker = '/usr/bin/arm-linux-gnueabihf-gcc'" >> /usr/local/cargo/config

ENV CC_x86_64_unknown_linux_musl="gcc" 
ENV CC_aarch64_unknown_linux_gnu="aarch64-linux-gnu-gcc" 
ENV CC_armv7_unknown_linux_gnueabhihf="arm-linux-gnueabihf-gcc"

# This is a bug fix for the windows cross compiler for Rust.
RUN cp /usr/x86_64-w64-mingw32/lib/crt2.o /usr/local/rustup/toolchains/1.38.0-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-pc-windows-gnu/lib/crt2.o

# For windows cross compilation, use a pre-build binary. Remember to set the
# SODIUM_LIB_DIR for windows cross compilation
RUN cd /opt && wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.17-mingw.tar.gz && \
    tar xvf libsodium-1.0.17-mingw.tar.gz     

# Cargo fetch the dependencies so we don't download them over and over again
RUN cd /tmp && git clone https://github.com/adityapk00/zecwallet-light-cli.git && \
    cd zecwallet-light-cli && \
    cargo fetch && \
    cd /tmp && rm -rf zecwallet-light-cli
