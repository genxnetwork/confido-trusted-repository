import base64
import hashlib
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sign_manual_endorsement import canonical_json, make_endorsement


class ManualEndorsementTests(unittest.TestCase):
    def test_signature_binds_subject_and_publisher_claim(self):
        digest = "a" * 64
        name = "teraveri/reference-value-registry/entries/example/manifest.json"
        predicate = {"publisher": "GENXT", "manifest_sha256": digest}
        key, bundle = make_endorsement(name, "sha256:" + digest, predicate)
        public_bytes = base64.b64decode(key["public_key"], validate=True)
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        self.assertEqual(hashlib.sha256(public_bytes).hexdigest(), bundle["key_id"])
        signature = base64.b64decode(bundle["signature"], validate=True)
        public_key.verify(signature, canonical_json(bundle["statement"]))
        bundle["statement"]["predicate"]["publisher"] = "other"
        with self.assertRaises(InvalidSignature):
            public_key.verify(signature, canonical_json(bundle["statement"]))


if __name__ == "__main__":
    unittest.main()
