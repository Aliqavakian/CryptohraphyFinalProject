# kps/shared_key_service.py
import hashlib
from typing import Optional, Set

from .key_server import KeyServer
from .models import User


class SharedKeyService:
    """
    Implements shared key generation between two users.

    Idea:
    - Each user has a subset of the global key pool.
    - We find all common key IDs.
    - Concatenate the actual key values and hash them with SHA-256.
    - The SHA-256 output (32 bytes) is used as an AES-256 key.
    """

    def __init__(self, server: KeyServer):
        self.server = server

    def _get_users(self, user_a_id: str, user_b_id: str) -> tuple[User, User]:
        user_a: Optional[User] = self.server.get_user(user_a_id)
        user_b: Optional[User] = self.server.get_user(user_b_id)

        if user_a is None or user_b is None:
            raise ValueError(
                "Both users must be registered before computing a shared key."
            )
        return user_a, user_b

    def common_key_ids(self, user_a_id: str, user_b_id: str) -> Set[int]:
        """
        Return the set of key IDs common to both users.
        """
        user_a, user_b = self._get_users(user_a_id, user_b_id)
        return user_a.key_ids.intersection(user_b.key_ids)

    def compute_shared_key(self, user_a_id: str, user_b_id: str) -> Optional[str]:
        """
        Compute the shared key between user A and user B as a hex string.

        Returns:
            - 64-char hex string (256-bit key), or
            - None if they have no common predistributed keys.
        """
        shared_ids = self.common_key_ids(user_a_id, user_b_id)

        if not shared_ids:
            return None


        material = b""
        for key_id in sorted(shared_ids):
            key_hex = self.server.get_key_value(key_id)
            material += bytes.fromhex(key_hex)


        derived = hashlib.sha256(material).hexdigest()
        return derived

    def compute_shared_key_bytes(
        self, user_a_id: str, user_b_id: str
    ) -> Optional[bytes]:
        """
        Same as compute_shared_key, but returns raw bytes (32 bytes for AES-256).
        """
        hex_key = self.compute_shared_key(user_a_id, user_b_id)
        if hex_key is None:
            return None
        return bytes.fromhex(hex_key)
