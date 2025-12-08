# kps/matrix_key_exchange.py
"""
Interactive matrix-based key agreement demo utilities.

The flow mirrors a simple symmetric-matrix construction:
- The server generates a random symmetric matrix ``S`` over a finite field ``Z_p``.
- Each user receives a random secret vector ``x`` and a public vector ``y = S * x (mod p)``.
- Two users derive the same shared scalar via ``x_a^T * y_b (mod p)`` and ``x_b^T * y_a (mod p)``
  because ``S`` is symmetric.
"""

from dataclasses import dataclass
import secrets
from typing import Dict, List


@dataclass
class MatrixUser:
    user_id: str
    secret_vector: List[int]
    public_vector: List[int]


class MatrixKeyServer:
    def __init__(self, prime: int, dimension: int):
        if prime <= 2:
            raise ValueError("Prime must be greater than 2")
        if dimension <= 0:
            raise ValueError("Dimension must be positive")

        self.prime = prime
        self.dimension = dimension
        self.secret_matrix: List[List[int]] = self._generate_symmetric_matrix()
        self._users: Dict[str, MatrixUser] = {}

    def _generate_symmetric_matrix(self) -> List[List[int]]:
        matrix = [[0 for _ in range(self.dimension)] for _ in range(self.dimension)]
        for i in range(self.dimension):
            for j in range(i, self.dimension):
                value = secrets.randbelow(self.prime)
                matrix[i][j] = value
                matrix[j][i] = value
        return matrix

    def _matrix_vector_product(self, vector: List[int]) -> List[int]:
        result: List[int] = []
        for row in self.secret_matrix:
            accum = sum((row[col] * vector[col]) for col in range(self.dimension))
            result.append(accum % self.prime)
        return result

    def register_user(self, user_id: str) -> MatrixUser:
        if user_id in self._users:
            return self._users[user_id]

        secret_vector = [secrets.randbelow(self.prime) for _ in range(self.dimension)]
        public_vector = self._matrix_vector_product(secret_vector)
        user = MatrixUser(user_id=user_id, secret_vector=secret_vector, public_vector=public_vector)
        self._users[user_id] = user
        return user

    def get_user(self, user_id: str) -> MatrixUser:
        if user_id not in self._users:
            raise KeyError(f"Unknown user: {user_id}")
        return self._users[user_id]

    def all_users(self) -> Dict[str, MatrixUser]:
        return dict(self._users)

    def compute_shared_value(self, sender_id: str, receiver_id: str) -> int:
        sender = self.get_user(sender_id)
        receiver = self.get_user(receiver_id)
        if len(sender.secret_vector) != self.dimension or len(receiver.public_vector) != self.dimension:
            raise ValueError("Vector dimensions do not match the configured dimension")

        shared = sum(
            s_val * r_val for s_val, r_val in zip(sender.secret_vector, receiver.public_vector)
        ) % self.prime
        return shared
