# kps/data_provisioning.py
import json
import os
from dataclasses import asdict
from typing import Dict

from .config import KeyDistributionConfig
from .key_server import KeyServer
from .models import Key, User


class DataProvisioningService:
    """
    Handles saving and loading the server state to/from a JSON file.

    This is the "data provisioning" part:
    - After generating keys and registering users, you can persist everything.
    - Later you can restore the exact same state from disk.
    """

    def __init__(self, server: KeyServer):
        self.server = server

    def _ensure_data_dir(self) -> str:
        cfg: KeyDistributionConfig = self.server.config
        os.makedirs(cfg.DATA_DIR, exist_ok=True)
        return cfg.DATA_DIR



    def save_state(self) -> str:
        """
        Save keys and users to a JSON file in DATA_DIR.
        Returns the path to the saved file.
        """
        data_dir = self._ensure_data_dir()
        path = os.path.join(data_dir, self.server.config.STATE_FILE)


        keys = {
            str(key_id): asdict(key)
            for key_id, key in self.server.get_all_keys().items()
        }


        users = {}
        for user_id, user in self.server.get_all_users().items():
            user_dict = asdict(user)
            user_dict["key_ids"] = list(user.key_ids)
            users[user_id] = user_dict

        state = {
            "config": asdict(self.server.config),
            "keys": keys,
            "users": users,
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=4)

        return path



    def load_state(self) -> None:
        """
        Load keys and users from the JSON file and update the server.
        """
        data_dir = self._ensure_data_dir()
        path = os.path.join(data_dir, self.server.config.STATE_FILE)

        if not os.path.exists(path):
            raise FileNotFoundError(f"No saved state found at: {path}")

        with open(path, "r", encoding="utf-8") as f:
            state = json.load(f)


        keys: Dict[int, Key] = {}
        for key_id_str, key_dict in state.get("keys", {}).items():
            key_id = int(key_id_str)
            keys[key_id] = Key(key_id=key_id, value=key_dict["value"])


        users: Dict[str, User] = {}
        for user_id, user_dict in state.get("users", {}).items():
            key_ids = set(user_dict.get("key_ids", []))
            users[user_id] = User(user_id=user_id, key_ids=key_ids)

        #
        self.server.replace_state(keys=keys, users=users)
