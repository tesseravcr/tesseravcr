FROM rust:latest AS builder

RUN git clone --depth 1 https://github.com/aws/aws-nitro-enclaves-nsm-api.git /build/nsm-api && \
    cd /build/nsm-api/nsm-lib && \
    cargo build --release

FROM python:3.11-slim

RUN apt-get update && apt-get install -y iproute2 && rm -rf /var/lib/apt/lists/*
RUN pip install boto3 cbor2

COPY --from=builder /build/nsm-api/target/release/libnsm.so /usr/lib/libnsm.so
COPY enclave_app.py /app/enclave_app.py

WORKDIR /app
ENTRYPOINT ["/usr/local/bin/python3", "/app/enclave_app.py"]
