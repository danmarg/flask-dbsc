import unittest
import time
import json
import uuid
from authlib.jose import jwt, jwk, JsonWebKey
from flask_dbsc.utils import verify_registration_jwt, verify_pop_jwt

class TestDBSCUtils(unittest.TestCase):
    def setUp(self):
        # Generate a test ES256 key pair
        self.key = JsonWebKey.generate_key(kty='EC', crv_or_size='P-256', is_private=True)
        # self.key is the private key object
        self.public_key_jwk = self.key.as_dict(is_private=False)

    def test_verify_registration_jwt(self):
        # Create a self-signed registration token
        header = {'alg': 'ES256', 'jwk': self.public_key_jwk}
        payload = {
            'iat': int(time.time()),
            'exp': int(time.time()) + 60,
            'jti': str(uuid.uuid4())
        }
        token = jwt.encode(header, payload, self.key)
        
        # Verify
        key, claims = verify_registration_jwt(token)
        self.assertEqual(key, self.public_key_jwk)
        self.assertEqual(claims['jti'], payload['jti'])

    def test_verify_pop_jwt(self):
        # Create a PoP token for refresh
        session_id = "test-session-123"
        refresh_url = "https://example.com/dbsc/refresh"
        
        header = {'alg': 'ES256'}
        payload = {
            'iat': int(time.time()),
            'exp': int(time.time()) + 60,
            'jti': str(uuid.uuid4()),
            'aud': refresh_url,
            'sub': session_id
        }
        token = jwt.encode(header, payload, self.key)
        
        # Verify
        claims = verify_pop_jwt(token, self.public_key_jwk, expected_aud=refresh_url, expected_sub=session_id)
        self.assertEqual(claims['sub'], session_id)
        self.assertEqual(claims['aud'], refresh_url)

    def test_verify_pop_jwt_mismatch(self):
        # Create a PoP token with wrong sub
        header = {'alg': 'ES256'}
        payload = {
            'iat': int(time.time()),
            'exp': int(time.time()) + 60,
            'aud': "https://example.com/dbsc/refresh",
            'sub': "wrong-session"
        }
        token = jwt.encode(header, payload, self.key)
        
        with self.assertRaises(ValueError) as cm:
            verify_pop_jwt(token, self.public_key_jwk, expected_sub="expected-session")
        self.assertIn("Subject mismatch", str(cm.exception))

if __name__ == '__main__':
    unittest.main()
