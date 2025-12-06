# app/main.py
from kps.config import KeyDistributionConfig
from kps.key_server import KeyServer
from kps.data_provisioning import DataProvisioningService
from kps.shared_key_service import SharedKeyService


def main() -> None:
    # 1) Create config and server
    config = KeyDistributionConfig(
        KEY_POOL_SIZE=50,   # you can change these numbers for experiments
        KEYS_PER_USER=8
    )
    server = KeyServer(config=config)

    # 2) Generate the global key pool (SERVER PART)
    server.generate_key_pool()

    # 3) Data provisioning service (save/load)
    data_service = DataProvisioningService(server)
    shared_service = SharedKeyService(server)

    # 4) Register some example users (key predistribution phase)
    alice = server.register_user("alice")
    bob = server.register_user("bob")
    carol = server.register_user("carol")

    print("=== Users and their assigned key IDs ===")
    for user in (alice, bob, carol):
        print(f"{user.user_id}: {sorted(user.key_ids)}")

    # 5) Shared key generation between users
    print("\n=== Shared keys between users ===")
    for u1, u2 in [("alice", "bob"), ("alice", "carol"), ("bob", "carol")]:
        shared_key = shared_service.compute_shared_key(u1, u2)
        if shared_key is None:
            print(f"{u1} ↔️ {u2}: NO common predistributed keys → no shared key.")
        else:
            print(f"{u1} ↔️ {u2}: shared key = {shared_key}")

    # 6) Save state to disk (DATA PROVISIONING)
    path = data_service.save_state()
    print(f"\nState saved to: {path}")

    # 7) (Optional) Show that we can load state back.
    #    In a real project you might restart the app and then call load_state().
    #    Here we just demonstrate it works.
    print("\nReloading state from disk to verify...")
    data_service.load_state()
    reloaded_alice = server.get_user("alice")
    print(f"Reloaded Alice has keys: {sorted(reloaded_alice.key_ids)}")


if __name__ == "__main__":
    main()