from dataclasses import dataclass


@dataclass(frozen=True)
class KeyDistributionConfig:
    """
    Configuration for the key predistribution system.
    Adjust these values if needed for experiments.
    """
    KEY_POOL_SIZE: int = 100      # How many keys the server generates in the pool
    KEYS_PER_USER: int = 10       # How many keys each user gets from the pool
    DATA_DIR: str = "data"        # Folder where JSON state will be saved
    STATE_FILE: str = "kps_state.json"
