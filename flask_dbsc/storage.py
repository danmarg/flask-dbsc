from abc import ABC, abstractmethod
import time

class BaseStore(ABC):
    @abstractmethod
    def store_key(self, session_id, public_key, metadata=None):
        pass

    @abstractmethod
    def get_key(self, session_id):
        pass

    @abstractmethod
    def remove_key(self, session_id):
        pass

class MemoryStore(BaseStore):
    def __init__(self, ttl=3600):
        self._store = {}
        self._ttl = ttl

    def store_key(self, session_id, public_key, metadata=None):
        self._store[session_id] = {
            'public_key': public_key,
            'metadata': metadata or {},
            'expires_at': time.time() + self._ttl
        }

    def get_key(self, session_id):
        data = self._store.get(session_id)
        if data and data['expires_at'] > time.time():
            return data['public_key'], data['metadata']
        elif data:
            self.remove_key(session_id)
        return None, None

    def remove_key(self, session_id):
        if session_id in self._store:
            del self._store[session_id]

    def cleanup(self):
        now = time.time()
        self._store = {k: v for k, v in self._store.items() if v['expires_at'] > now}
