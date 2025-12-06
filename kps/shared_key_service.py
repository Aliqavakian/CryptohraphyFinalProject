import hashlib
from typing import Optional

from .key_server import KeyServer
from .models import User


class SharedKeyService:
    """
    Implements shared key generation between two users.

    Idea (basic key predistribution):
    - Each user has a subset of the global key pool.
    - The shared key is derived from all common keys they both have.
    - If there are no common keys, there is no shared key.
    """

    def __init__(self, server: KeyServer):
        self.server = server

    def compute_shared_key(self, user_a_id: str, user_b_id: str) -> Optional[str]:
        """
        Compute the shared key between user A and user B.
        Returns:
            - hex string of the derived key, or
            - None if they have no common predistributed keys.
        """
        user_a: Optional[User] = self.server.get_user(user_a_id)
        user_b: Optional[User] = self.server.get_user(user_b_id)

        if user_a is None or user_b is None:
            raise ValueError("Both users must be registered before computing a shared key.")

        shared_ids = user_a.key_ids.intersection(user_b.key_ids)

        if not shared_ids:
            return None

        # Concatenate the actual key values (in a fixed order) and hash them.
        material = b""
        for key_id in sorted(shared_ids):
            key_hex = self.server.get_key_value(key_id)
            material += bytes.fromhex(key_hex)

        # SHA-256 to derive a final shared key
        derived = hashlib.sha256(material).hexdigest()
        return derived
