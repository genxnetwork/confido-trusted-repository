#!/usr/bin/env python3
"""Prepare a reviewed GENXT publisher statement for an immutable registry entry."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.request

REGISTRY = "teraveri/attestation-references"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REQUEST_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
SAFE = re.compile(r"[A-Za-z0-9_.-]+\Z")
MAX_FILE = 4 * 1024 * 1024


def object_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(data):
    return json.loads(data, object_pairs_hook=object_no_duplicates)


def safe_path(value):
    return isinstance(value, str) and bool(value) and all(
        part not in (".", "..") and SAFE.fullmatch(part)
        for part in value.split("/")
    )


def fetch(commit, path):
    if not isinstance(commit, str) or not HEX40.fullmatch(commit) or not safe_path(path):
        raise ValueError("invalid immutable registry locator")
    url = f"https://api.github.com/repos/{REGISTRY}/contents/{path}?ref={commit}"
    headers = {"Accept": "application/vnd.github.raw+json", "User-Agent": "genxt-reference-endorsement/1"}
    if token := os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=20) as response:
        data = response.read(MAX_FILE + 1)
    if not data or len(data) > MAX_FILE:
        raise ValueError(f"invalid registry object size: {path}")
    return data


def prepare(root, request_id, reader=fetch):
    if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
        raise ValueError("invalid request ID")
    request = parse_json((root / "endorsement-requests" / f"{request_id}.json").read_bytes())
    if set(request) != {"schema_version", "registry_repository", "registry_commit", "manifest_path", "manifest_sha256"}:
        raise ValueError("invalid request shape")
    commit = request["registry_commit"]
    path = request["manifest_path"]
    digest = request["manifest_sha256"]
    if request["schema_version"] != 1 or request["registry_repository"] != REGISTRY:
        raise ValueError("unexpected registry")
    if not isinstance(commit, str) or not HEX40.fullmatch(commit):
        raise ValueError("invalid registry commit")
    if not safe_path(path) or not path.startswith("entries/") or not path.endswith("/manifest.json"):
        raise ValueError("invalid manifest path")
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        raise ValueError("invalid manifest digest")
    manifest_bytes = reader(commit, path)
    if hashlib.sha256(manifest_bytes).hexdigest() != digest:
        raise ValueError("manifest digest mismatch")
    manifest = parse_json(manifest_bytes)
    reference = manifest["reference"]
    reference_path = path.removesuffix("manifest.json") + "reference.json"
    if manifest["schema_version"] != 1 or manifest["profile"] != "azure-snp-vtpm-ima/1":
        raise ValueError("unsupported manifest profile")
    if manifest["id"] != path.split("/")[-2] or manifest["environment"]["product"] not in ("Milan", "Genoa"):
        raise ValueError("manifest identity mismatch")
    if manifest["provenance"]["review_status"] not in ("stage-candidate", "stage-approved", "approved"):
        raise ValueError("unreviewed status")
    if reference["path"] != reference_path or not isinstance(reference["sha256"], str) or not HEX64.fullmatch(reference["sha256"]):
        raise ValueError("invalid reference descriptor")
    reference_bytes = reader(commit, reference_path)
    if hashlib.sha256(reference_bytes).hexdigest() != reference["sha256"]:
        raise ValueError("reference digest mismatch")
    reference_object = parse_json(reference_bytes)
    if not isinstance(reference_object.get("ima_measurements"), list) or type(reference["ima_entries"]) is not int or len(reference_object["ima_measurements"]) != reference["ima_entries"]:
        raise ValueError("reference measurement count mismatch")
    predicate = {
        "schema_version": 1,
        "claim": "published-reference-manifest",
        "publisher": "GENXT",
        "registry_repository": REGISTRY,
        "manifest_path": path,
        "manifest_sha256": digest,
    }
    return f"{REGISTRY}/{path}", f"sha256:{digest}", predicate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()
    name, digest, predicate = prepare(args.root, args.request_id)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    predicate_path = args.output_dir / "predicate.json"
    predicate_path.write_text(json.dumps(predicate, separators=(",", ":")) + "\n")
    with args.github_output.open("a") as output:
        output.write(f"subject_name={name}\nsubject_digest={digest}\npredicate_path={predicate_path}\n")
    print(f"prepared reviewed request {args.request_id}: {name} {digest}")


if __name__ == "__main__":
    main()
