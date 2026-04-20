#!/usr/bin/env python3
"""
Generate a real ZK proof using ezkl.

Creates a tiny ONNX model (linear classifier: 3 inputs -> 2 outputs),
runs the full ezkl Halo2 pipeline, and saves proof artifacts as JSON
for use by the VCR demo.

Usage:
    python3 examples/zk-prove/prove.py

Outputs:
    examples/zk-prove/sample_proof.json   — proof + public inputs + metadata
    examples/zk-prove/artifacts/           — ezkl intermediate files (vk, pk, srs, etc.)
"""

import hashlib
import json
import os
import tempfile

import ezkl
import numpy as np
import onnx
from onnx import TensorProto, helper


def build_model(weights, bias):
    """Build a minimal ONNX model: y = xW^T + b (linear classifier)."""
    # Input: [1, 3] — three sensor readings
    X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 3])
    # Output: [1, 2] — two class scores (safe / unsafe)
    Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 2])

    W = helper.make_tensor("W", TensorProto.FLOAT, [2, 3], weights.flatten().tolist())
    B = helper.make_tensor("B", TensorProto.FLOAT, [2], bias.tolist())

    # Gemm: Y = X @ W^T + B
    gemm = helper.make_node("Gemm", ["X", "W", "B"], ["Y"], transB=1)

    graph = helper.make_graph([gemm], "linear_classifier", [X], [Y], [W, B])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    return model


def run_pipeline(work_dir):
    """Run the full ezkl pipeline: settings -> compile -> setup -> prove -> verify."""

    # Fixed weights: a simple risk classifier
    weights = np.array([[0.5, -0.3, 0.8], [-0.2, 0.6, -0.4]], dtype=np.float32)
    bias = np.array([0.1, -0.1], dtype=np.float32)
    input_data = np.array([[0.7, 0.3, 0.9]], dtype=np.float32)

    # File paths
    model_path = os.path.join(work_dir, "model.onnx")
    data_path = os.path.join(work_dir, "input.json")
    settings_path = os.path.join(work_dir, "settings.json")
    compiled_path = os.path.join(work_dir, "compiled.ezkl")
    srs_path = os.path.join(work_dir, "kzg.srs")
    vk_path = os.path.join(work_dir, "vk.key")
    pk_path = os.path.join(work_dir, "pk.key")
    witness_path = os.path.join(work_dir, "witness.json")
    proof_path = os.path.join(work_dir, "proof.json")

    # 1. Save model and input
    model = build_model(weights, bias)
    onnx.save(model, model_path)

    input_json = {"input_data": [input_data.flatten().tolist()]}
    with open(data_path, "w") as f:
        json.dump(input_json, f)

    print("  [1/7] Model saved (linear classifier: 3 inputs -> 2 outputs)")

    # 2. Generate circuit settings
    ezkl.gen_settings(model_path, settings_path, py_run_args=None)
    print("  [2/7] Circuit settings generated")

    # 3. Calibrate
    ezkl.calibrate_settings(
        data_path, model_path, settings_path,
        target="resources",
        lookup_safety_margin=2.0,
        scales=None,
        scale_rebase_multiplier=[1],
        max_logrows=None,
    )
    print("  [3/7] Settings calibrated")

    # 4. Compile circuit
    ezkl.compile_circuit(model_path, compiled_path, settings_path)
    print("  [4/7] Circuit compiled")

    # Read logrows from settings for SRS generation
    with open(settings_path) as f:
        settings = json.load(f)
    logrows = settings["run_args"]["logrows"]

    # 5. Generate SRS + setup (vk/pk)
    ezkl.gen_srs(srs_path, logrows)
    ezkl.setup(compiled_path, vk_path, pk_path, srs_path,
               witness_path=None, disable_selector_compression=False)
    print(f"  [5/7] Trusted setup complete (logrows={logrows})")

    # 6. Generate witness + prove
    ezkl.gen_witness(data_path, compiled_path, witness_path,
                     vk_path=None, srs_path=None)
    ezkl.prove(witness_path, compiled_path, pk_path, proof_path, srs_path)
    print("  [6/7] Proof generated")

    # 7. Verify
    verified = ezkl.verify(proof_path, settings_path, vk_path, srs_path,
                           reduced_srs=False)
    print(f"  [7/7] Proof verified: {verified}")

    if not verified:
        raise RuntimeError("Proof verification failed!")

    # Read proof and build output
    with open(proof_path) as f:
        proof_data = json.load(f)

    with open(vk_path, "rb") as f:
        vk_bytes = f.read()

    # Compute hashes for VCR receipt fields
    input_bytes = json.dumps(input_json, separators=(",", ":")).encode()
    input_hash = hashlib.sha256(input_bytes).hexdigest()

    # Output is the public outputs from the witness/proof
    output_bytes = json.dumps(proof_data.get("pretty_public_inputs", {}),
                              separators=(",", ":")).encode()
    output_hash = hashlib.sha256(output_bytes).hexdigest()

    vk_id = hashlib.sha256(vk_bytes).hexdigest()

    # proof bytes = the hex-encoded proof from ezkl
    proof_hex = proof_data["hex_proof"]
    proof_bytes_raw = bytes.fromhex(proof_hex.removeprefix("0x"))

    result = {
        "model": "linear_classifier",
        "model_description": "3 sensor inputs -> 2 risk scores (safe/unsafe)",
        "input_data": input_data.flatten().tolist(),
        "input_hash": input_hash,
        "output_hash": output_hash,
        "proof_hex": proof_hex,
        "public_inputs": proof_data.get("pretty_public_inputs", {}),
        "verification_key_id": vk_id,
        "logrows": logrows,
        "proof_size_bytes": len(proof_bytes_raw),
    }

    return result


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    artifacts_dir = os.path.join(script_dir, "artifacts")
    output_path = os.path.join(script_dir, "sample_proof.json")

    os.makedirs(artifacts_dir, exist_ok=True)

    print()
    print("  Generating ZK proof with ezkl (Halo2)...")
    print()

    result = run_pipeline(artifacts_dir)

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print()
    print(f"  Saved: {output_path}")
    print(f"  Proof size: {result['proof_size_bytes']:,} bytes")
    print(f"  VK ID: {result['verification_key_id'][:24]}...")
    print()


if __name__ == "__main__":
    main()
