# kps/config.py
from dataclasses import dataclass


@dataclass(frozen=True)
class KeyDistributionConfig:
    """
    Configuration for the key predistribution system.
    Adjust these values if needed for experiments.
    """
    KEY_POOL_SIZE: int = 100
    KEYS_PER_USER: int = 10
    DATA_DIR: str = "data"
    STATE_FILE: str = "kps_state.json"
