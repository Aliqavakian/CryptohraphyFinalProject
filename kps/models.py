from dataclasses import dataclass, field
from typing import Set


@dataclass
class Key:
    """
    Represents a single key in the global key pool.
    value is stored as hex string to make JSON saving easy.
    """
    key_id: int
    value: str  # hex string


@dataclass
class User:
    """
    Represents a user in the system.
    key_ids is the set of key IDs assigned to this user.
    """
    user_id: str
    key_ids: Set[int] = field(default_factory=set)
