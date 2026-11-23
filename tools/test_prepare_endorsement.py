import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from prepare_endorsement import prepare

SOURCE = Path(__file__).resolve().parents[1]
REGISTRY = SOURCE.parent / "attestation-references"
ENTRY = "entries/azure-snp-vtpm-ima-1/azure-genoa-ubuntu2204-kernel-1071-stage"


class PrepareEndorsementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "endorsement-requests").mkdir()
        self.request_file = self.root / "endorsement-requests/genoa-stage-1071.json"
        shutil.copyfile(SOURCE / "endorsement-requests/genoa-stage-1071.json", self.request_file)
        self.manifest_path = f"{ENTRY}/manifest.json"
        self.manifest_bytes = (REGISTRY / self.manifest_path).read_bytes()
        self.reference_path = f"{ENTRY}/reference.json"
        self.reference_bytes = (REGISTRY / self.reference_path).read_bytes()
        self.objects = {self.manifest_path: self.manifest_bytes, self.reference_path: self.reference_bytes}

    def reader(self, commit, path):
        self.assertEqual(commit, "b21a16b6129a36000bfe7fdc60d5dd2cd285e3fa")
        return self.objects[path]

    def update_request(self, edit):
        request = json.loads(self.request_file.read_text())
        edit(request)
        self.request_file.write_text(json.dumps(request) + "\n")

    def test_prepares_exact_manifest_subject(self):
        name, digest, predicate = prepare(self.root, "genoa-stage-1071", self.reader)
        expected = hashlib.sha256(self.manifest_bytes).hexdigest()
        self.assertEqual(name, f"teraveri/attestation-references/{self.manifest_path}")
        self.assertEqual(digest, f"sha256:{expected}")
        self.assertEqual(predicate["manifest_sha256"], expected)
        self.assertEqual(predicate["publisher"], "GENXT")

    def test_rejects_wrong_manifest_digest(self):
        self.update_request(lambda r: r.update(manifest_sha256="0" * 64))
        with self.assertRaisesRegex(ValueError, "manifest digest mismatch"):
            prepare(self.root, "genoa-stage-1071", self.reader)

    def test_rejects_changed_reference(self):
        self.objects[self.reference_path] += b" "
        with self.assertRaisesRegex(ValueError, "reference digest mismatch"):
            prepare(self.root, "genoa-stage-1071", self.reader)

    def test_rejects_path_escape(self):
        with self.assertRaisesRegex(ValueError, "invalid request ID"):
            prepare(self.root, "../../other", self.reader)

    def test_rejects_unreviewed_status(self):
        manifest = json.loads(self.manifest_bytes)
        manifest["provenance"]["review_status"] = "withdrawn"
        self.objects[self.manifest_path] = json.dumps(manifest).encode()
        self.update_request(lambda r: r.update(manifest_sha256=hashlib.sha256(self.objects[self.manifest_path]).hexdigest()))
        with self.assertRaisesRegex(ValueError, "unreviewed status"):
            prepare(self.root, "genoa-stage-1071", self.reader)


if __name__ == "__main__":
    unittest.main()
