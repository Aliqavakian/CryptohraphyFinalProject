import random
import secrets
from typing import Dict, Optional

from .config import KeyDistributionConfig
from .models import Key, User


class KeyServer:
    """
    Central server for the key predistribution scheme.

    Responsibilities:
    - Generate a pool of random keys.
    - Register users and assign each of them a random subset of keys.
    - Provide read access to keys and user information.
    """

    def __init__(self, config: Optional[KeyDistributionConfig] = None):
        self.config: KeyDistributionConfig = config or KeyDistributionConfig()
        self._keys: Dict[int, Key] = {}
        self._users: Dict[str, User] = {}

    # ------------- SERVER PART: KEY POOL GENERATION -------------

    def generate_key_pool(self) -> None:
        """
        Generate the global key pool with KEY_POOL_SIZE random keys.
        """
        self._keys.clear()
        for key_id in range(self.config.KEY_POOL_SIZE):
            # 128-bit random key, stored as hex
            value = secrets.token_hex(16)
            self._keys[key_id] = Key(key_id=key_id, value=value)

    # ------------- SERVER PART: USER REGISTRATION -------------

    def register_user(self, user_id: str) -> User:
        """
        Register a new user and assign KEYS_PER_USER random keys.
        If the user already exists, simply return it.
        """
        if not self._keys:
            raise RuntimeError("Key pool is empty. Call generate_key_pool() first.")

        if user_id in self._users:
            return self._users[user_id]

        if self.config.KEYS_PER_USER > len(self._keys):
            raise ValueError(
                "Not enough keys in the pool to assign KEYS_PER_USER per user."
            )

        key_ids = set(random.sample(list(self._keys.keys()), self.config.KEYS_PER_USER))
        user = User(user_id=user_id, key_ids=key_ids)
        self._users[user_id] = user
        return user

    # ------------- ACCESSORS -------------

    def get_user(self, user_id: str) -> Optional[User]:
        return self._users.get(user_id)

    def get_all_users(self) -> Dict[str, User]:
        return dict(self._users)

    def get_all_keys(self) -> Dict[int, Key]:
        return dict(self._keys)

    def get_key_value(self, key_id: int) -> str:
        return self._keys[key_id].value

    # ------------- USED BY DATA PROVISIONING -------------

    def replace_state(self, keys: Dict[int, Key], users: Dict[str, User]) -> None:
        """
        Replace current in-memory state with the provided dictionaries.
        Used by DataProvisioningService when loading from disk.
        """
        self._keys = keys
        self._users = users
