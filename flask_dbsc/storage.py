import json
import time
from abc import ABC, abstractmethod


class BaseStore(ABC):
    @abstractmethod
    def store_key(self, session_id, public_key, metadata=None, ttl=3600):
        pass

    @abstractmethod
    def get_key(self, session_id):
        """Returns (public_key, metadata) or (None, None) if missing/expired."""
        pass

    @abstractmethod
    def remove_key(self, session_id):
        pass

    @abstractmethod
    def store_challenge(self, challenge, ttl=300):
        pass

    @abstractmethod
    def consume_challenge(self, challenge):
        """Validate and consume a challenge (one-time use). Raises ValueError if invalid."""
        pass


class MemoryStore(BaseStore):
    """Simple in-memory store. Fine for development; loses state on restart."""

    def __init__(self, ttl=3600):
        self._ttl = ttl
        self._sessions = {}    # session_id -> (public_key, metadata, expires_at)
        self._challenges = {}  # challenge -> expires_at

    def store_key(self, session_id, public_key, metadata=None, ttl=None):
        self._sessions[session_id] = (public_key, metadata or {}, time.time() + (ttl or self._ttl))

    def get_key(self, session_id):
        entry = self._sessions.get(session_id)
        if not entry:
            return None, None
        public_key, metadata, expires_at = entry
        if time.time() > expires_at:
            del self._sessions[session_id]
            return None, None
        return public_key, metadata

    def remove_key(self, session_id):
        self._sessions.pop(session_id, None)

    def store_challenge(self, challenge, ttl=300):
        self._challenges[challenge] = time.time() + ttl

    def consume_challenge(self, challenge):
        expiry = self._challenges.pop(challenge, None)
        if expiry is None:
            raise ValueError(f"Unknown or already-used challenge: {challenge!r}")
        if time.time() > expiry:
            raise ValueError("Challenge has expired")


class SQLAlchemyStore(BaseStore):
    """
    Flask-SQLAlchemy-backed store.

    The developer defines their own model classes using the provided mixins
    and passes them in. This keeps the models visible to Alembic autogenerate
    and lets the developer customise them (e.g. add a FK to their User model).

    Typical setup::

        from flask_sqlalchemy import SQLAlchemy
        from flask_dbsc import DBSC, SQLAlchemyStore
        from flask_dbsc.models import DBSCSessionMixin, DBSCChallengeMixin

        db = SQLAlchemy()

        class DBSCSession(db.Model, DBSCSessionMixin):
            __tablename__ = 'dbsc_sessions'

        class DBSCChallenge(db.Model, DBSCChallengeMixin):
            __tablename__ = 'dbsc_challenges'

        dbsc = DBSC(storage=SQLAlchemyStore(db, DBSCSession, DBSCChallenge))
    """

    def __init__(self, db, session_model, challenge_model):
        self.db = db
        self.DBSCSession = session_model
        self.DBSCChallenge = challenge_model

    # --- sessions ---

    def store_key(self, session_id, public_key, metadata=None, ttl=3600):
        row = self.db.session.get(self.DBSCSession, session_id)
        if row is None:
            row = self.DBSCSession(session_id=session_id)
            self.db.session.add(row)
        row.public_key    = json.dumps(public_key)
        row.metadata_json = json.dumps(metadata)
        row.expires_at    = time.time() + ttl
        self.db.session.commit()

    def get_key(self, session_id):
        row = self.db.session.get(self.DBSCSession, session_id)
        if row is None:
            return None, None
        if time.time() > row.expires_at:
            self.remove_key(session_id)
            return None, None
        return json.loads(row.public_key), json.loads(row.metadata_json) if row.metadata_json else None

    def remove_key(self, session_id):
        row = self.db.session.get(self.DBSCSession, session_id)
        if row:
            self.db.session.delete(row)
            self.db.session.commit()

    # --- challenges ---

    def store_challenge(self, challenge, ttl=300):
        row = self.db.session.get(self.DBSCChallenge, challenge)
        if row is None:
            row = self.DBSCChallenge(challenge=challenge)
            self.db.session.add(row)
        row.expires_at = time.time() + ttl
        self.db.session.commit()

    def consume_challenge(self, challenge):
        row = self.db.session.get(self.DBSCChallenge, challenge)
        if row is None:
            raise ValueError(f"Unknown or already-used challenge: {challenge!r}")
        expired = time.time() > row.expires_at
        self.db.session.delete(row)
        self.db.session.commit()
        if expired:
            raise ValueError("Challenge has expired")
