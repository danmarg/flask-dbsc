import base64
import json
from authlib.jose import jwt, jwk
import time
import uuid

def verify_registration_jwt(token, expected_aud=None):
    """
    Verifies the self-signed registration JWT from the browser.
    Extracts the JWK from the header and uses it to verify the signature.
    Returns (public_key_jwk, claims).
    """
    try:
        if isinstance(token, bytes):
            token = token.decode('utf-8')

        # Manually extract header from JWT (header.payload.signature)
        header_segment = token.split('.')[0]
        # Pad base64 string
        missing_padding = len(header_segment) % 4
        if missing_padding:
            header_segment += '=' * (4 - missing_padding)

        header_data = base64.urlsafe_b64decode(header_segment)
        header = json.loads(header_data)

        # Issue #5: validate typ claim per spec §9.10
        if header.get('typ') != 'dbsc+jwt':
            raise ValueError(f"Invalid typ: expected 'dbsc+jwt', got {header.get('typ')!r}")

        public_key_jwk = header.get('jwk')
        if not public_key_jwk:
            raise ValueError("Missing JWK in registration token header")

        # Verify signature with the provided JWK
        claims = jwt.decode(token, public_key_jwk)
        claims.validate()

        # Issue #4: validate aud against the registration endpoint URL
        if expected_aud and claims.get('aud') != expected_aud:
            raise ValueError(f"Audience mismatch: expected {expected_aud!r}, got {claims.get('aud')!r}")

        return public_key_jwk, claims
    except Exception as e:
        raise ValueError(f"Invalid registration token: {str(e)}")

def verify_pop_jwt(token, public_key_jwk, expected_aud=None, expected_sub=None):
    """
    Verifies the Proof of Possession (PoP) JWT from the browser.
    """
    try:
        # Verify signature with the stored public key
        claims = jwt.decode(token, public_key_jwk)

        if expected_aud and claims.get('aud') != expected_aud:
            raise ValueError(f"Audience mismatch: expected {expected_aud}, got {claims.get('aud')}")

        if expected_sub and claims.get('sub') != expected_sub:
            raise ValueError(f"Subject mismatch: expected {expected_sub}, got {claims.get('sub')}")

        claims.validate()
        return claims
    except Exception as e:
        raise ValueError(f"Invalid PoP token: {str(e)}")

def generate_session_instructions(session_id, origin, refresh_url, cookie_name):
    """
    Generates the DBSC JSON response for registration and refresh.
    Uses the scope structure defined in the spec (§9.6).
    """
    # Parse hostname from origin for scope_specification
    from urllib.parse import urlparse
    hostname = urlparse(origin).hostname or origin

    return {
        "session_identifier": session_id,
        "refresh_url": refresh_url,
        "scope": {
            # Issue #1: correct spec scope shape
            "origin": origin,
            "include_site": True,
            "scope_specification": [
                {"type": "include", "domain": hostname, "path": "/"}
            ]
        },
        "credentials": [
            {
                "type": "cookie",
                "name": cookie_name,
                "attributes": "Secure; HttpOnly; SameSite=Strict; Path=/"
            }
        ]
    }
