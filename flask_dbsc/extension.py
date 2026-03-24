from flask import request, make_response, jsonify, current_app, url_for
import uuid
from .storage import MemoryStore
from .utils import (
    verify_registration_jwt,
    verify_pop_jwt,
    generate_session_instructions
)

class DBSC:
    def __init__(self, app=None, storage=None, config=None):
        self.storage = storage or MemoryStore()
        self.config = config or {
            'cookie_name': 'dbsc_session',
            'registration_path': '/dbsc/register',
            'refresh_path': '/dbsc/refresh',
            'supported_algos': '(ES256 RS256)'
        }
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.add_url_rule(self.config['registration_path'], 'dbsc_register', self.handle_register, methods=['POST'])
        app.add_url_rule(self.config['refresh_path'], 'dbsc_refresh', self.handle_refresh, methods=['POST'])
        app.extensions['dbsc'] = self

    def initiate(self, response, challenge=None):
        """
        Adds the Secure-Session-Registration header to initiate DBSC on the browser.
        """
        if challenge is None:
            challenge = str(uuid.uuid4())

        self.storage.store_challenge(challenge, ttl=300)

        header_val = (
            f"{self.config['supported_algos']}"
            f";path=\"{self.config['registration_path']}\""
            f";challenge=\"{challenge}\""
        )
        response.headers['Secure-Session-Registration'] = header_val
        return response

    def handle_register(self):
        """
        Endpoint called by the browser to register the public key.
        """
        # The browser sends the registration JWT in the Secure-Session-Response header
        # as an sf-string (RFC 9651), so strip the surrounding quotes.
        raw = request.headers.get('Secure-Session-Response', '')
        token = raw.strip().strip('"')
        try:
            reg_url = url_for('dbsc_register', _external=True)
            public_key, claims = verify_registration_jwt(token, expected_aud=reg_url)

            jti = claims.get('jti')
            self.storage.consume_challenge(jti)

            dbsc_session_id = str(uuid.uuid4())

            # Store the key
            self.storage.store_key(dbsc_session_id, public_key, metadata={
                'user_agent': request.user_agent.string,
                'remote_addr': request.remote_addr
            })

            # Return session instructions
            origin = request.scheme + '://' + request.host
            instructions = generate_session_instructions(
                session_id=dbsc_session_id,
                origin=origin,
                refresh_url=self.config['refresh_path'],
                cookie_name=self.config['cookie_name']
            )

            resp = make_response(jsonify(instructions))
            # Set the initial short-lived bound cookie
            resp.set_cookie(self.config['cookie_name'], dbsc_session_id,
                            secure=True, httponly=True, samesite='Strict', max_age=600)
            return resp

        except Exception as e:
            return jsonify({"error": "Registration failed", "details": str(e)}), 400

    def handle_refresh(self):
        """
        Endpoint called by the browser when the bound cookie needs refresh.
        """
        raw_id = request.headers.get('Sec-Secure-Session-Id') or request.headers.get('Sec-Session-Id', '')
        session_id = raw_id.strip().strip('"')

        if not session_id:
            # Also check the cookie
            session_id = request.cookies.get(self.config['cookie_name'])

        if not session_id:
            return jsonify({"error": "Missing session identifier"}), 401

        public_key, metadata = self.storage.get_key(session_id)
        if not public_key:
            return jsonify({"error": "Session not found or expired"}), 403

        # The browser sends the PoP JWT in the Secure-Session-Response header
        # as an sf-string (RFC 9651), so strip the surrounding quotes.
        raw = request.headers.get('Secure-Session-Response', '')
        token = raw.strip().strip('"')
        try:
            # Using url_for ensures it respects ProxyFix/X-Forwarded-Proto
            refresh_url = url_for('dbsc_refresh', _external=True)
            verify_pop_jwt(token, public_key, expected_aud=refresh_url, expected_sub=session_id)

            # Issue new short-lived cookie
            origin = request.scheme + '://' + request.host
            instructions = generate_session_instructions(
                session_id=session_id,
                origin=origin,
                refresh_url=self.config['refresh_path'],
                cookie_name=self.config['cookie_name']
            )
            resp = make_response(jsonify(instructions))
            resp.set_cookie(self.config['cookie_name'], session_id,
                            secure=True, httponly=True, samesite='Strict', max_age=600)
            return resp

        except Exception as e:
            challenge = str(uuid.uuid4())
            resp = make_response(jsonify({"error": "PoP verification failed", "details": str(e)}), 403)
            resp.headers['Secure-Session-Challenge'] = f'"{challenge}";id="{session_id}"'
            return resp

    def is_authenticated(self):
        """
        Utility to check if the current request is DBSC-authenticated.
        """
        session_id = request.cookies.get(self.config['cookie_name'])
        if not session_id:
            return False

        public_key, _ = self.storage.get_key(session_id)
        return public_key is not None
