import json
import hashlib
import socket
import traceback
import threading
import ctypes

VSOCK_PORT = 5000
PROXY_PORT = 8443
PARENT_CID = 3
BEDROCK_HOST = "bedrock-runtime.us-west-2.amazonaws.com"
BEDROCK_REGION = "us-west-2"
MODEL_ID = "anthropic.claude-3-haiku-20240307-v1:0"


def forward(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            src.close()
        except Exception:
            pass
        try:
            dst.close()
        except Exception:
            pass


def tcp_to_vsock_proxy():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 443))
    server.listen(5)
    while True:
        client, addr = server.accept()
        vsock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        vsock.connect((PARENT_CID, PROXY_PORT))
        threading.Thread(target=forward, args=(client, vsock), daemon=True).start()
        threading.Thread(target=forward, args=(vsock, client), daemon=True).start()


def get_attestation_doc(user_data: bytes) -> bytes:
    """Request attestation from the Nitro Security Module via libnsm.so.
    user_data is embedded in the hardware-signed attestation document."""
    nsm = ctypes.CDLL("/usr/lib/libnsm.so")

    P_U8 = ctypes.POINTER(ctypes.c_uint8)
    P_U32 = ctypes.POINTER(ctypes.c_uint32)

    nsm.nsm_lib_init.argtypes = []
    nsm.nsm_lib_init.restype = ctypes.c_int
    fd = nsm.nsm_lib_init()
    if fd < 0:
        raise RuntimeError(f"nsm_lib_init failed: {fd}")

    MAX_DOC = 16384
    att_doc_buf = (ctypes.c_uint8 * MAX_DOC)()
    att_doc_len = ctypes.c_uint32(MAX_DOC)
    ud_arr = (ctypes.c_uint8 * len(user_data))(*user_data)

    nsm.nsm_get_attestation_doc.argtypes = [
        ctypes.c_int,          # fd
        P_U8, ctypes.c_uint32, # user_data, user_data_len
        P_U8, ctypes.c_uint32, # nonce, nonce_len
        P_U8, ctypes.c_uint32, # public_key, public_key_len
        P_U8,                  # att_doc_data (output buffer)
        P_U32,                 # att_doc_len (input: capacity, output: actual size)
    ]
    nsm.nsm_get_attestation_doc.restype = ctypes.c_uint32

    ret = nsm.nsm_get_attestation_doc(
        fd,
        ud_arr, ctypes.c_uint32(len(user_data)),
        None, ctypes.c_uint32(0),
        None, ctypes.c_uint32(0),
        att_doc_buf,
        ctypes.byref(att_doc_len),
    )

    nsm.nsm_lib_exit(fd)

    if ret != 0:
        raise RuntimeError(f"nsm_get_attestation_doc failed: error code {ret}")

    return bytes(att_doc_buf[:att_doc_len.value])


def call_bedrock(prompt: str, credentials: dict) -> str:
    import boto3
    from botocore.config import Config
    bedrock = boto3.client(
        service_name="bedrock-runtime",
        region_name=BEDROCK_REGION,
        endpoint_url=f"https://{BEDROCK_HOST}",
        aws_access_key_id=credentials["access_key"],
        aws_secret_access_key=credentials["secret_key"],
        aws_session_token=credentials.get("token"),
        config=Config(proxies={}),
    )
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 256,
        "messages": [{"role": "user", "content": prompt}],
    })
    response = bedrock.invoke_model(body=body, modelId=MODEL_ID)
    result = json.loads(response["body"].read())
    return result["content"][0]["text"]


def handle_request(prompt: str, credentials: dict) -> dict:
    try:
        import cbor2
        input_bytes = prompt.encode("utf-8")
        input_hash = hashlib.sha256(input_bytes).digest()
        output_text = call_bedrock(prompt, credentials)
        output_bytes = output_text.encode("utf-8")
        output_hash = hashlib.sha256(output_bytes).digest()
        user_data = cbor2.dumps({
            "input_hash": input_hash,
            "output_hash": output_hash,
        })
        attestation_doc = get_attestation_doc(user_data)
        return {
            "output": output_text,
            "input_hash": input_hash.hex(),
            "output_hash": output_hash.hex(),
            "attestation": attestation_doc.hex(),
        }
    except Exception as e:
        traceback.print_exc()
        return {"error": str(e)}


def main():
    import subprocess
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)

    with open("/etc/hosts", "a") as f:
        f.write(f"\n127.0.0.1 {BEDROCK_HOST}\n")

    threading.Thread(target=tcp_to_vsock_proxy, daemon=True).start()

    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.bind((socket.VMADDR_CID_ANY, VSOCK_PORT))
    sock.listen(1)
    print(f"Enclave listening on vsock port {VSOCK_PORT}", flush=True)
    while True:
        conn, addr = sock.accept()
        try:
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            request = json.loads(data.decode("utf-8"))
            prompt = request["prompt"]
            credentials = request["credentials"]
            result = handle_request(prompt, credentials)
            response = json.dumps(result).encode("utf-8")
            conn.sendall(response)
        except Exception as e:
            traceback.print_exc()
            error = json.dumps({"error": str(e)}).encode("utf-8")
            conn.sendall(error)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
