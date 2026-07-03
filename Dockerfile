FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y -qq && \
    apt-get install -y -qq software-properties-common curl git cmake build-essential \
    pkg-config libssl-dev binutils python3 python3-venv python3-pip python3-dev \
    clang llvm libbpf-dev linux-headers-generic ca-certificates

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app
COPY . .

RUN NSYNC_SKIP_NATIVE=1 cargo build --release --bin gateway

EXPOSE 8088
CMD sh -c "NSYNC_GATEWAY_PORT=8088 ./target/release/gateway"
