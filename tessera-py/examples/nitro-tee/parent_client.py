import json
import socket
import sys
import boto3

ENCLAVE_CID = 16  # check with: nitro-cli describe-enclaves
VSOCK_PORT = 5000


def get_credentials():
    session = boto3.Session()
    creds = session.get_credentials().get_frozen_credentials()
    return {
        "access_key": creds.access_key,
        "secret_key": creds.secret_key,
        "token": creds.token,
    }


def call_enclave(prompt: str) -> dict:
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.connect((ENCLAVE_CID, VSOCK_PORT))

    creds = get_credentials()
    request = json.dumps({"prompt": prompt, "credentials": creds}).encode("utf-8")
    sock.sendall(request)
    sock.shutdown(socket.SHUT_WR)

    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    sock.close()

    return json.loads(data.decode("utf-8"))


if __name__ == "__main__":
    prompt = sys.argv[1] if len(sys.argv) > 1 else "What is 2+2?"
    print(f"Sending to enclave: {prompt}")
    result = call_enclave(prompt)

    if "error" in result:
        print(f"Error: {result['error']}")
        sys.exit(1)

    print(f"Output: {result['output']}")
    print(f"Input hash: {result['input_hash']}")
    print(f"Output hash: {result['output_hash']}")
    print(f"Attestation: {result['attestation'][:80]}...")
    print(f"Attestation size: {len(result['attestation']) // 2} bytes")

    # Save to JSON for offline verification
    save_path = "result.json"
    save_data = {
        "prompt": prompt,
        "output": result["output"],
        "input_hash": result["input_hash"],
        "output_hash": result["output_hash"],
        "attestation": result["attestation"],
    }
    with open(save_path, "w") as f:
        json.dump(save_data, f, indent=2)
    print(f"\nSaved to {save_path} — verify with:")
    print(f"  python3 ../../tools/verify_attestation.py --file {save_path}")
