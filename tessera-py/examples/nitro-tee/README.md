# Nitro TEE Attestation Example

Hardware-rooted attestation for AI inference using AWS Nitro Enclaves. Demonstrates the `tee-nitro-v1` proving backend for VCRs.

## What this does

1. Parent EC2 instance sends a prompt + IAM credentials to the enclave via vsock
2. Enclave calls Claude (Bedrock) through a vsock-proxy tunnel
3. Enclave hashes the input and output (SHA-256)
4. Enclave requests a hardware attestation document from the Nitro Security Module, embedding the input/output hashes as user_data
5. Returns the output, hashes, and attestation document to the parent

The attestation document is a COSE Sign1 structure signed by the Nitro hardware root of trust. It contains PCR measurements (proving which code ran) and the embedded user_data (proving which input/output hashes the enclave committed to). Anyone can verify it against AWS's public certificate chain.

## Files

- `enclave_app.py` — Runs inside the enclave. Handles Bedrock calls, hashing, and NSM attestation.
- `parent_client.py` — Runs on the parent EC2 instance. Sends prompts via vsock.
- `Dockerfile` — Multi-stage build. Compiles AWS's nsm-lib (Rust FFI) in the builder stage, produces a slim Python image with libnsm.so.

## Prerequisites

- EC2 instance with Nitro Enclave support (c5.xlarge or larger)
- `nitro-cli` and `docker` installed
- IAM role with Bedrock access
- vsock-proxy configured for `bedrock-runtime.us-west-2.amazonaws.com:443`

## Setup

### 1. Configure vsock-proxy

Add to `/etc/nitro_enclaves/vsock-proxy.yaml`:

```yaml
- {address: bedrock-runtime.us-west-2.amazonaws.com, port: 443}
```

### 2. Build and run

```bash
# Build Docker image
docker build -t claude-enclave .

# Build enclave image
nitro-cli build-enclave --docker-uri claude-enclave:latest --output-file claude.eif

# Start vsock-proxy (terminal 1)
vsock-proxy 8443 bedrock-runtime.us-west-2.amazonaws.com 443

# Run enclave (terminal 2)
nitro-cli run-enclave --eif-path claude.eif --cpu-count 2 --memory 4096

# Check CID
nitro-cli describe-enclaves

# Update ENCLAVE_CID in parent_client.py, then run (terminal 3)
python3 parent_client.py "What is 2+2?"
```

### 3. Expected output

```
Sending to enclave: What is 2+2?
Output: 4
Input hash: 52cb6b5e4a038af1756708f98afb718a08c75b87b2f03dbee4dd9c8139c15c5e
Output hash: 4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a
Attestation: 8444a1013822a059115ebf696d6f64756c655f69647827692d306630326363...
Attestation size: 4554 bytes
```

## How it maps to VCR fields

| VCR field | Value |
|---|---|
| `proving_backend` | `"tee-nitro-v1"` |
| `proof` | Raw attestation document (~4.5 KB COSE Sign1) |
| `public_inputs` | PCR0, PCR1, PCR2 values from `nitro-cli build-enclave` |
| `input_hash` | SHA-256 of the prompt |
| `output_hash` | SHA-256 of the model response |

## Verifying the attestation

The attestation document is a COSE Sign1 structure containing:

- **PCR0**: Hash of the enclave image (code identity)
- **PCR1**: Hash of the Linux kernel and bootstrap
- **PCR2**: Hash of the application
- **user_data**: CBOR-encoded `{input_hash, output_hash}`
- **certificate**: Signed by AWS Nitro Attestation PKI

Verification: decode the COSE Sign1, validate the certificate chain against AWS's root CA, check the PCR values match the expected enclave build, and confirm the user_data contains the expected hashes.

## Architecture

```
Parent EC2                              Nitro Enclave
  |                                       |
  |-- prompt + creds (vsock:5000) ------->|
  |                                       |-- loopback:443 -> vsock:8443 --|
  |<-- vsock-proxy:8443 <-- HTTPS --------|    (TCP-to-vsock proxy)        |
  |-- HTTPS --> bedrock API ------------->|                                 |
  |                                       |<-- Bedrock response ----------|
  |                                       |-- SHA-256(input, output)
  |                                       |-- NSM attestation(/dev/nsm)
  |<-- output + hashes + attestation -----|
```
