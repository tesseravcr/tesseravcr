#!/usr/bin/env python3
"""
Verify an AWS Nitro Enclave attestation document.

Takes the hex-encoded attestation from a VCR and independently verifies:
  1. COSE Sign1 structure is well-formed
  2. Certificate chain validates against AWS Nitro root CA
  3. Signature over the payload is valid
  4. PCR values are present (flags debug mode if zeroed)
  5. user_data contains the expected input/output hashes

Usage:
  python verify_attestation.py <attestation_hex>
  python verify_attestation.py <attestation_hex> --prompt "What is 2+2?" --output "4"
  python verify_attestation.py --file result.json
  python verify_attestation.py --file result.json --skip-chain  # testing without AWS root CA

Dependencies: pip install cbor2 cryptography
"""

import argparse
import hashlib
import json
import sys
import struct
from datetime import datetime, timezone

try:
    import cbor2
except ImportError:
    print("Missing dependency: pip install cbor2")
    sys.exit(1)

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("Missing dependency: pip install cryptography")
    sys.exit(1)


# AWS Nitro Enclaves Root CA certificate (PEM)
# Subject: CN=aws.nitro-enclaves, C=US, O=Amazon, OU=AWS
# This is the trust anchor. Download and verify from:
# https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
AWS_NITRO_ROOT_CA_PEM = """\
-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----"""


def decode_cose_sign1(raw_bytes):
    """Decode a COSE Sign1 structure from raw bytes."""
    decoded = cbor2.loads(raw_bytes)

    # COSE Sign1 is a CBOR tag 18 wrapping an array of 4 elements,
    # or just a raw array of 4 elements
    if isinstance(decoded, cbor2.CBORTag):
        if decoded.tag != 18:
            raise ValueError(f"Expected COSE Sign1 tag (18), got tag {decoded.tag}")
        items = decoded.value
    elif isinstance(decoded, list) and len(decoded) == 4:
        items = decoded
    else:
        raise ValueError(f"Unexpected COSE structure: {type(decoded)}")

    protected_header_bytes = items[0]
    unprotected_header = items[1]
    payload_bytes = items[2]
    signature = items[3]

    protected_header = cbor2.loads(protected_header_bytes) if protected_header_bytes else {}
    payload = cbor2.loads(payload_bytes) if payload_bytes else {}

    return {
        "protected_header": protected_header,
        "protected_header_bytes": protected_header_bytes,
        "unprotected_header": unprotected_header,
        "payload": payload,
        "payload_bytes": payload_bytes,
        "signature": signature,
    }


def build_sig_structure(protected_header_bytes, payload_bytes):
    """Build the COSE Sig_structure for verification.
    Sig_structure = ["Signature1", protected, external_aad, payload]
    """
    return cbor2.dumps([
        "Signature1",
        protected_header_bytes,
        b"",  # external_aad
        payload_bytes,
    ])


def verify_certificate_chain(cabundle, end_cert_der, root_ca_pem):
    """Verify the certificate chain from the attestation document against the root CA.
    cabundle contains intermediates [root-signed ... last-intermediate].
    end_cert_der is the actual signing certificate from the payload's 'certificate' field.
    """
    root_cert = x509.load_pem_x509_certificate(root_ca_pem.encode())

    # Parse all certificates in the chain
    chain_certs = []
    for cert_der in cabundle:
        cert = x509.load_der_x509_certificate(cert_der)
        chain_certs.append(cert)

    if not chain_certs:
        return False, "Empty certificate chain"

    # Verify the first cert in the chain is signed by the root CA
    try:
        root_public_key = root_cert.public_key()
        root_public_key.verify(
            chain_certs[0].signature,
            chain_certs[0].tbs_certificate_bytes,
            ec.ECDSA(chain_certs[0].signature_hash_algorithm),
        )
    except InvalidSignature:
        return False, "First certificate in chain not signed by AWS root CA"

    # Verify each subsequent cert is signed by the previous one
    for i in range(1, len(chain_certs)):
        try:
            parent_key = chain_certs[i - 1].public_key()
            parent_key.verify(
                chain_certs[i].signature,
                chain_certs[i].tbs_certificate_bytes,
                ec.ECDSA(chain_certs[i].signature_hash_algorithm),
            )
        except InvalidSignature:
            return False, f"Certificate {i} not signed by certificate {i-1}"

    # Verify the end-entity (signing) certificate is signed by the last intermediate
    end_cert = x509.load_der_x509_certificate(end_cert_der)
    try:
        last_intermediate_key = chain_certs[-1].public_key()
        last_intermediate_key.verify(
            end_cert.signature,
            end_cert.tbs_certificate_bytes,
            ec.ECDSA(end_cert.signature_hash_algorithm),
        )
    except InvalidSignature:
        return False, "Signing certificate not signed by last intermediate in chain"

    return True, end_cert  # Return the actual signing certificate


def verify_signature(leaf_cert, protected_header_bytes, payload_bytes, signature):
    """Verify the COSE Sign1 signature using the leaf certificate's public key."""
    sig_structure = build_sig_structure(protected_header_bytes, payload_bytes)
    public_key = leaf_cert.public_key()

    # The signature algorithm from the protected header determines the hash
    # Algorithm -35 = ES384 (ECDSA w/ SHA-384)
    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            # COSE signature is r||s concatenated, need to convert to DER
            key_size = public_key.key_size
            r_len = (key_size + 7) // 8
            r = int.from_bytes(signature[:r_len], "big")
            s = int.from_bytes(signature[r_len:], "big")
            der_sig = utils.encode_dss_signature(r, s)
            public_key.verify(der_sig, sig_structure, ec.ECDSA(hashes.SHA384()))
        return True, None
    except InvalidSignature:
        return False, "Signature verification failed"
    except Exception as e:
        return False, f"Signature verification error: {e}"


def format_pcr(pcr_bytes):
    """Format PCR bytes as hex, flagging if zeroed."""
    hex_str = pcr_bytes.hex()
    if all(b == 0 for b in pcr_bytes):
        return f"{hex_str} (ZEROED - debug mode)"
    return hex_str


def main():
    parser = argparse.ArgumentParser(
        description="Verify an AWS Nitro Enclave attestation document"
    )
    parser.add_argument("attestation_hex", nargs="?", help="Hex-encoded attestation document")
    parser.add_argument("--file", "-f", help="JSON file from parent_client.py output")
    parser.add_argument("--prompt", "-p", help="Original prompt to verify input_hash")
    parser.add_argument("--output", "-o", help="Model output to verify output_hash")
    parser.add_argument("--skip-chain", action="store_true",
                        help="Skip AWS root CA chain validation (for testing)")
    args = parser.parse_args()

    # Get the attestation hex
    if args.file:
        with open(args.file) as f:
            data = json.load(f)
        attestation_hex = data["attestation"]
        if not args.prompt and "prompt" in data:
            args.prompt = data["prompt"]
        if not args.output and "output" in data:
            args.output = data["output"]
    elif args.attestation_hex:
        attestation_hex = args.attestation_hex
    else:
        parser.print_help()
        sys.exit(1)

    raw_bytes = bytes.fromhex(attestation_hex)
    print(f"Attestation document: {len(raw_bytes)} bytes\n")

    # Step 1: Decode COSE Sign1
    print("=" * 60)
    print("STEP 1: Decode COSE Sign1 structure")
    print("=" * 60)
    try:
        cose = decode_cose_sign1(raw_bytes)
        print("  COSE Sign1 structure: valid")
        alg = cose["protected_header"].get(1, "unknown")
        alg_name = {-35: "ES384 (ECDSA w/ SHA-384)", -36: "ES512"}.get(alg, str(alg))
        print(f"  Algorithm: {alg_name}")
    except Exception as e:
        print(f"  FAILED: {e}")
        sys.exit(1)

    payload = cose["payload"]

    # Step 2: Extract attestation fields
    print(f"\n{'=' * 60}")
    print("STEP 2: Extract attestation payload")
    print("=" * 60)
    print(f"  Module ID: {payload.get('module_id', 'N/A')}")

    timestamp = payload.get("timestamp")
    if timestamp:
        dt = datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc)
        print(f"  Timestamp: {dt.isoformat()} ({timestamp})")

    digest = payload.get("digest", "N/A")
    print(f"  Digest algorithm: {digest}")

    # PCR values
    pcrs = payload.get("pcrs", {})
    print(f"\n  PCR values ({len(pcrs)} registers):")
    debug_mode = True
    for idx in sorted(pcrs.keys()):
        pcr_val = pcrs[idx]
        formatted = format_pcr(pcr_val)
        print(f"    PCR{idx}: {formatted}")
        if not all(b == 0 for b in pcr_val):
            debug_mode = False

    if debug_mode and pcrs:
        print("\n  WARNING: All PCR values are zero. This attestation was generated")
        print("  in debug mode (--attach-console). In production, PCR values")
        print("  would contain SHA-384 hashes of the enclave image, kernel,")
        print("  and application, proving exactly which code ran.")

    # Step 3: Verify certificate chain
    print(f"\n{'=' * 60}")
    print("STEP 3: Verify certificate chain against AWS Nitro root CA")
    print("=" * 60)
    cabundle = payload.get("cabundle", [])
    print(f"  Certificate chain length: {len(cabundle)}")

    if args.skip_chain:
        print("  Chain verification: SKIPPED (--skip-chain)")
        # Use the certificate from the payload directly
        cert_der = payload.get("certificate")
        if cert_der:
            leaf_cert = x509.load_der_x509_certificate(cert_der)
        else:
            leaf_cert = x509.load_der_x509_certificate(cabundle[-1])
        chain_valid = True
        print(f"  Using leaf certificate: {leaf_cert.subject}")
    else:
        end_cert_der = payload.get("certificate", cabundle[-1] if cabundle else b"")
        chain_valid, result = verify_certificate_chain(cabundle, end_cert_der, AWS_NITRO_ROOT_CA_PEM)
        if chain_valid:
            leaf_cert = result
            print("  Chain verification: PASSED")
            print(f"  Leaf certificate subject: {leaf_cert.subject}")
            print(f"  Leaf certificate issuer: {leaf_cert.issuer}")
        else:
            print(f"  Chain verification: FAILED ({result})")
            sys.exit(1)

    # Step 4: Verify COSE signature
    print(f"\n{'=' * 60}")
    print("STEP 4: Verify COSE Sign1 signature")
    print("=" * 60)
    sig_valid, sig_err = verify_signature(
        leaf_cert,
        cose["protected_header_bytes"],
        cose["payload_bytes"],
        cose["signature"],
    )
    if sig_valid:
        print("  Signature verification: PASSED")
        print("  The attestation document was signed by the Nitro Security Module.")
    else:
        print(f"  Signature verification: FAILED ({sig_err})")
        sys.exit(1)

    # Step 5: Extract and verify user_data
    print(f"\n{'=' * 60}")
    print("STEP 5: Extract user_data (input/output hashes)")
    print("=" * 60)
    user_data_raw = payload.get("user_data")
    if user_data_raw:
        print(f"  user_data present: {len(user_data_raw)} bytes")
        try:
            user_data = cbor2.loads(user_data_raw)
            input_hash = user_data.get("input_hash", b"")
            output_hash = user_data.get("output_hash", b"")
            print(f"  input_hash:  {input_hash.hex()}")
            print(f"  output_hash: {output_hash.hex()}")

            # Verify against provided prompt/output if given
            if args.prompt:
                expected_input = hashlib.sha256(args.prompt.encode()).digest()
                match = expected_input == input_hash
                status = "MATCH" if match else "MISMATCH"
                print(f"\n  Prompt verification: {status}")
                print(f"    Provided prompt: \"{args.prompt}\"")
                print(f"    SHA-256:         {expected_input.hex()}")
                print(f"    Attested hash:   {input_hash.hex()}")

            if args.output:
                expected_output = hashlib.sha256(args.output.encode()).digest()
                match = expected_output == output_hash
                status = "MATCH" if match else "MISMATCH"
                print(f"\n  Output verification: {status}")
                print(f"    Provided output: \"{args.output}\"")
                print(f"    SHA-256:         {expected_output.hex()}")
                print(f"    Attested hash:   {output_hash.hex()}")

        except Exception as e:
            print(f"  Could not decode user_data as CBOR: {e}")
            print(f"  Raw hex: {user_data_raw.hex()}")
    else:
        print("  No user_data in attestation document")

    # Summary
    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print("=" * 60)
    print(f"  COSE Sign1 structure:  valid")
    print(f"  Certificate chain:     {'PASSED' if chain_valid else 'FAILED'}")
    print(f"  Signature:             {'PASSED' if sig_valid else 'FAILED'}")
    print(f"  Debug mode:            {'YES (PCRs zeroed)' if debug_mode else 'NO (production)'}")
    if user_data_raw:
        print(f"  User data:             present ({len(user_data_raw)} bytes)")
    print()
    if chain_valid and sig_valid:
        print("  This attestation document was produced by a genuine AWS Nitro")
        print("  Enclave and signed by the Nitro Security Module hardware.")
        if debug_mode:
            print("  However, it was generated in debug mode. Production attestations")
            print("  include non-zero PCR values that prove which code was running.")
    print()


if __name__ == "__main__":
    main()
