#!/usr/bin/env python3
"""Issue a one-use, key-pinned GENXT stage endorsement without GitHub Actions.

The private key exists only in this process. The verifier must explicitly pin
the public key; repository publication alone is not an authorization.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from prepare_endorsement import MAX_FILE, prepare, safe_path

PREDICATE_TYPE = "https://teraveri.org/attestations/reference-manifest-publisher/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
REPOSITORY = "genxnetwork/confido-trusted-repository"


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def make_endorsement(name, digest, predicate):
    if not digest.startswith("sha256:"):
        raise ValueError("unsupported subject digest")
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": name, "digest": {"sha256": digest.removeprefix("sha256:")}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = hashlib.sha256(public_key).hexdigest()
    signature = private_key.sign(canonical_json(statement))
    declaration = {
        "schema_version": 1,
        "publisher": "GENXT",
        "repository": REPOSITORY,
        "purpose": "one-use-stage-reference-endorsement",
        "algorithm": "Ed25519",
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "public_key_sha256": key_id,
    }
    bundle = {
        "schema_version": 1,
        "algorithm": "Ed25519",
        "key_id": key_id,
        "statement": statement,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    return declaration, bundle


def local_reader(registry_dir):
    root = registry_dir.resolve(strict=True)
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True,
                          capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain=v1"], check=True,
                           capture_output=True, text=True).stdout
    if dirty:
        raise ValueError("local registry checkout must be clean")

    def read(commit, path):
        if commit != head or not safe_path(path):
            raise ValueError("local registry commit or path mismatch")
        file = (root / path).resolve(strict=True)
        if not file.is_relative_to(root) or not file.is_file():
            raise ValueError("registry object escapes checkout")
        data = file.read_bytes()
        if not data or len(data) > MAX_FILE:
            raise ValueError("invalid registry object size")
        return data

    return read


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--registry-dir", type=Path, help="Clean checkout at the pinned registry commit")
    args = parser.parse_args()
    reader = local_reader(args.registry_dir) if args.registry_dir else None
    name, digest, predicate = prepare(args.root, args.request_id, reader=reader) if reader else prepare(args.root, args.request_id)
    declaration, bundle = make_endorsement(name, digest, predicate)
    key_path = args.root / "publisher-keys" / "genxt-stage-ed25519.json"
    bundle_path = args.root / "manual-endorsements" / f"{args.request_id}.ed25519.json"
    if key_path.exists() or bundle_path.exists():
        raise FileExistsError("manual stage key or endorsement already exists")
    key_path.parent.mkdir(parents=True, exist_ok=True)
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(json.dumps(declaration, indent=2) + "\n")
    bundle_path.write_text(json.dumps(bundle, indent=2) + "\n")
    print(f"signed {name} {digest} with one-use key {declaration['public_key_sha256']}")


if __name__ == "__main__":
    main()
