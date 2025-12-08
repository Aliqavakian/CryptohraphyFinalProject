# app/main.py
"""Demo script for the key predistribution system."""

import argparse
import os
import sys

# Ensure the project root (which contains the ``kps`` package) is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from kps.config import KeyDistributionConfig
from kps.key_server import KeyServer
from kps.data_provisioning import DataProvisioningService
from kps.shared_key_service import SharedKeyService
from kps.aes_cipher import AESCipher
from kps.matrix_key_exchange import MatrixKeyServer


def print_user_key_rings(server: KeyServer) -> None:
    print("=== User key rings (key_id -> key_value_hex) ===")
    for user in server.get_all_users().values():
        print(f"User {user.user_id}:")
        for key_id in sorted(user.key_ids):
            key_value = server.get_key_value(key_id)
            print(f"  key_id = {key_id:2d}   value = {key_value}")
        print()


def print_user_key_assignment_matrix(server: KeyServer) -> None:
    print("=== User–key assignment matrix ===")
    users = sorted(server.get_all_users().values(), key=lambda u: u.user_id)
    key_ids = sorted(server.get_all_keys().keys())

    header = "      " + " ".join(f"{kid:2d}" for kid in key_ids)
    print(header)
    print("      " + "--" * len(key_ids))

    for user in users:
        row = ["1" if kid in user.key_ids else "0" for kid in key_ids]
        print(f"{user.user_id:5s} " + "  ".join(row))
    print()


def print_pairwise_common_keys_matrix(
    server: KeyServer, shared_service: SharedKeyService
) -> None:
    print("=== Pairwise common-keys matrix (entries = number of shared keys) ===")
    users = sorted(server.get_all_users().values(), key=lambda u: u.user_id)
    ids = [u.user_id for u in users]

    header = "      " + " ".join(f"{uid:5s}" for uid in ids)
    print(header)
    print("      " + "-" * (6 * len(ids)))

    for u1 in ids:
        row_counts = []
        for u2 in ids:
            common = shared_service.common_key_ids(u1, u2)
            row_counts.append(len(common))
        row_str = " ".join(f"{c:5d}" for c in row_counts)
        print(f"{u1:5s} {row_str}")
    print()


def _prompt_int(prompt: str, minimum: int = 1) -> int:
    while True:
        raw = input(prompt).strip()
        try:
            value = int(raw)
            if value < minimum:
                print(f"Please enter a number >= {minimum}.")
                continue
            return value
        except ValueError:
            print("Please enter a valid integer.")


def _print_matrix(matrix) -> None:
    for row in matrix:
        print("  " + " ".join(f"{val:4d}" for val in row))


def run_matrix_key_agreement_demo() -> None:
    import hashlib

    print("Step 1: Server Setup")
    prime = _prompt_int("Enter a prime modulus p: ", minimum=3)
    dimension = _prompt_int("Enter the matrix dimension: ", minimum=1)

    server = MatrixKeyServer(prime=prime, dimension=dimension)
    print("\nGenerated symmetric secret matrix S:")
    _print_matrix(server.secret_matrix)

    print("\nStep 2: User Registration")
    num_users = _prompt_int("How many users to register? ", minimum=1)

    for idx in range(1, num_users + 1):
        user_id = ""
        while not user_id:
            user_id = input(f"Enter user #{idx} ID: ").strip()
            if not user_id:
                print("User ID cannot be empty.")

        user = server.register_user(user_id)
        print(f"User '{user.user_id}' registered.")
        print(f"  Secret vector (x): {user.secret_vector}")
        print(f"  Public vector (S*x mod p): {user.public_vector}\n")

    if num_users < 2:
        print("Need at least two users to establish a shared key.")
        return

    print("Step 3: Key Agreement Between Users")
    registered_ids = list(server.all_users().keys())
    print(f"Registered users: {', '.join(registered_ids)}")

    while True:
        pair_input = input("Enter two user IDs separated by space: ").split()
        if len(pair_input) != 2:
            print("Please provide exactly two user IDs.")
            continue
        user_a, user_b = pair_input
        if user_a not in server.all_users() or user_b not in server.all_users():
            print("Both IDs must correspond to registered users.")
            continue
        break

    shared_a = server.compute_shared_value(user_a, user_b)
    shared_b = server.compute_shared_value(user_b, user_a)

    print(f"\n{user_a} computes shared key with {user_b}: {shared_a} (mod {prime})")
    print(f"{user_b} computes shared key with {user_a}: {shared_b} (mod {prime})")
    if shared_a == shared_b:
        print("Keys match! A shared secret has been established.\n")
    else:
        print("Keys do not match. Something went wrong.\n")
        return

    print("Step 4 (Optional): Encryption Test")
    message = input("Enter a message to encrypt (leave blank to skip): ")
    if not message:
        print("Skipped encryption demo.")
        return

    derived_key = hashlib.sha256(str(shared_a).encode("utf-8")).digest()
    aes = AESCipher(derived_key)
    nonce, ciphertext, tag = aes.encrypt(message.encode("utf-8"))
    decrypted = aes.decrypt(nonce, ciphertext, tag).decode("utf-8")

    print("\nEncryption with derived key:")
    print(f"  Nonce      (hex): {nonce.hex()}")
    print(f"  Ciphertext (hex): {ciphertext.hex()}")
    print(f"  Tag        (hex): {tag.hex()}")
    print(f"  Decrypted message: {decrypted}")
    print("\nCommunication verified using the shared secret.")


def run_cli_demo() -> None:
    config = KeyDistributionConfig(
        KEY_POOL_SIZE=50,
        KEYS_PER_USER=8
    )
    server = KeyServer(config=config)

    server.generate_key_pool()

    data_service = DataProvisioningService(server)
    shared_service = SharedKeyService(server)

    alice = server.register_user("alice")
    bob = server.register_user("bob")
    carol = server.register_user("carol")

    print("=== Users and their assigned key IDs ===")
    for user in (alice, bob, carol):
        print(f"{user.user_id}: {sorted(user.key_ids)}")
    print()

    print_user_key_rings(server)

    print_user_key_assignment_matrix(server)

    print_pairwise_common_keys_matrix(server, shared_service)

    print("=== Shared keys between users (derived via SHA-256) ===")
    pairs = [("alice", "bob"), ("alice", "carol"), ("bob", "carol")]
    for u1, u2 in pairs:
        shared_key_hex = shared_service.compute_shared_key(u1, u2)
        if shared_key_hex is None:
            print(f"{u1} ↔️ {u2}: NO common predistributed keys → no shared key.")
        else:
            print(f"{u1} ↔️ {u2}: shared key (hex) = {shared_key_hex}")
    print()

    print("=== AES demo using derived shared key ===")

    demo_pair = None
    demo_key_bytes = None

    for u1, u2 in pairs:
        key_bytes = shared_service.compute_shared_key_bytes(u1, u2)
        if key_bytes is not None:
            demo_pair = (u1, u2)
            demo_key_bytes = key_bytes
            break

    if demo_pair is None:
        print("No user pair shares any keys → cannot run AES demo.")
    else:
        u1, u2 = demo_pair
        aes_key = demo_key_bytes
        aes = AESCipher(aes_key)

        plaintext = f"Hello from {u1} to {u2} via AES!".encode("utf-8")
        nonce, ciphertext, tag = aes.encrypt(plaintext)
        decrypted = aes.decrypt(nonce, ciphertext, tag)

        print(f"Using pair: {u1} & {u2}")
        print(f"Derived AES key (hex): {aes_key.hex()}")
        print(f"Nonce       (hex): {nonce.hex()}")
        print(f"Ciphertext  (hex): {ciphertext.hex()}")
        print(f"Tag         (hex): {tag.hex()}")
        print(f"Decrypted plaintext: {decrypted.decode('utf-8')}")
    print()

    path = data_service.save_state()
    print(f"State saved to: {path}")

    print("\nReloading state from disk to verify...")
    data_service.load_state()
    reloaded_alice = server.get_user("alice")
    print(f"Reloaded Alice has keys: {sorted(reloaded_alice.key_ids)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Key predistribution demo")
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the Tkinter GUI instead of the CLI demo",
    )
    parser.add_argument(
        "--matrix-demo",
        action="store_true",
        help="Run the interactive matrix-based key agreement demo",
    )
    args = parser.parse_args()

    if args.gui:
        from app.gui import launch_gui

        launch_gui()
    elif args.matrix_demo:
        run_matrix_key_agreement_demo()
    else:
        run_cli_demo()


if __name__ == "__main__":
    main()
