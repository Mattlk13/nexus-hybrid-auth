"""Regression coverage for JWT configuration and claim boundaries."""
import os
import unittest
from unittest.mock import patch
import jwt
from nexus_hybrid_auth import HybridAuthService


class AuthenticationBoundaries(unittest.TestCase):
    def make_service(self, secret=None):
        with patch.dict(os.environ, {}, clear=True):
            if secret is not None:
                os.environ["JWT_SECRET"] = secret
            return HybridAuthService()

    def test_missing_and_weak_configuration_cannot_sign_or_verify(self):
        for secret in (None, "", "nexus-secret", "short", " " * 32):
            with self.subTest(configured=secret is not None):
                service = self.make_service(secret)
                with self.assertRaises(ValueError):
                    service.create_jwt_token("user-1", "person@example.test")
                self.assertFalse(service.verify_jwt_token("untrusted-token")["valid"])

    def test_configured_round_trip_preserves_identity(self):
        service = self.make_service("unit-test-signing-material-" + "a" * 32)
        token = service.create_jwt_token("user-1", "person@example.test", custom_claims={"workspace": "lab"})
        result = service.verify_jwt_token(token)
        self.assertTrue(result["valid"])
        self.assertEqual(result["payload"]["user_id"], "user-1")
        self.assertEqual(result["payload"]["workspace"], "lab")

    def test_custom_claims_cannot_override_authority_or_lifetime(self):
        service = self.make_service("unit-test-signing-material-" + "a" * 32)
        for claim in ("user_id", "email", "role", "exp", "iat", "nbf", "iss", "aud", "sub", "jti"):
            with self.subTest(claim=claim):
                with self.assertRaises(ValueError):
                    service.create_jwt_token("user-1", "person@example.test", custom_claims={claim: "override"})

    def test_other_signing_key_is_rejected(self):
        service = self.make_service("unit-test-signing-material-" + "a" * 32)
        other = self.make_service("unit-test-signing-material-" + "b" * 32)
        token = other.create_jwt_token("user-1", "person@example.test")
        self.assertFalse(service.verify_jwt_token(token)["valid"])

    def test_signed_token_missing_required_claims_is_rejected(self):
        service = self.make_service("unit-test-signing-material-" + "a" * 32)
        token = jwt.encode({"user_id": "user-1"}, service.jwt_secret, algorithm="HS256")
        self.assertFalse(service.verify_jwt_token(token)["valid"])


if __name__ == "__main__":
    unittest.main()
