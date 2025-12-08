"""
A lightweight Tkinter GUI for exploring the key predistribution project.

The interface guides you through initializing the key server, registering
users, deriving shared keys, and performing a simple authenticated
encryption demo using the derived key material.
"""

import os
import sys
import tkinter as tk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText

# Ensure the project root (which contains the ``kps`` package) is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from kps.config import KeyDistributionConfig
from kps.key_server import KeyServer
from kps.data_provisioning import DataProvisioningService
from kps.shared_key_service import SharedKeyService
from kps.aes_cipher import AESCipher


class KeyDistributionGUI:
    """Interactive GUI for the key predistribution system."""

    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("Key Predistribution Demo")

        self.config: KeyDistributionConfig | None = None
        self.server: KeyServer | None = None
        self.data_service: DataProvisioningService | None = None
        self.shared_service: SharedKeyService | None = None

        self._build_ui()

    # ------------------------------------------------------------------
    # UI helpers
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)

        self._build_config_frame()
        self._build_user_frame()
        self._build_shared_key_frame()
        self._build_aes_frame()
        self._build_output_area()

    def _build_config_frame(self) -> None:
        frame = tk.LabelFrame(self.root, text="1. Configure & Initialize")
        frame.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
        frame.columnconfigure(3, weight=1)

        tk.Label(frame, text="Key pool size:").grid(row=0, column=0, sticky="w")
        self.pool_entry = tk.Entry(frame, width=10)
        self.pool_entry.insert(0, "50")
        self.pool_entry.grid(row=0, column=1, padx=(0, 10))

        tk.Label(frame, text="Keys per user:").grid(row=0, column=2, sticky="w")
        self.keys_entry = tk.Entry(frame, width=10)
        self.keys_entry.insert(0, "8")
        self.keys_entry.grid(row=0, column=3, sticky="w")

        init_btn = tk.Button(frame, text="Initialize", command=self.initialize_system)
        init_btn.grid(row=0, column=4, padx=10)

    def _build_user_frame(self) -> None:
        frame = tk.LabelFrame(self.root, text="2. Register Users")
        frame.grid(row=1, column=0, sticky="ew", padx=10, pady=5)
        frame.columnconfigure(1, weight=1)

        tk.Label(frame, text="User ID:").grid(row=0, column=0, sticky="w")
        self.user_entry = tk.Entry(frame)
        self.user_entry.grid(row=0, column=1, sticky="ew", padx=(0, 10))

        add_btn = tk.Button(frame, text="Register", command=self.register_user)
        add_btn.grid(row=0, column=2, padx=5)

        list_btn = tk.Button(frame, text="List Users", command=self.list_users)
        list_btn.grid(row=0, column=3, padx=5)

    def _build_shared_key_frame(self) -> None:
        frame = tk.LabelFrame(self.root, text="3. Shared Keys")
        frame.grid(row=2, column=0, sticky="ew", padx=10, pady=5)
        for col in range(4):
            frame.columnconfigure(col, weight=1)

        tk.Label(frame, text="User A:").grid(row=0, column=0, sticky="w")
        self.user_a_entry = tk.Entry(frame)
        self.user_a_entry.grid(row=0, column=1, sticky="ew", padx=(0, 10))

        tk.Label(frame, text="User B:").grid(row=0, column=2, sticky="w")
        self.user_b_entry = tk.Entry(frame)
        self.user_b_entry.grid(row=0, column=3, sticky="ew", padx=(0, 10))

        compute_btn = tk.Button(frame, text="Compute Shared Key", command=self.compute_shared_key)
        compute_btn.grid(row=1, column=0, columnspan=4, pady=4)

    def _build_aes_frame(self) -> None:
        frame = tk.LabelFrame(self.root, text="4. AES Demo (using derived key)")
        frame.grid(row=3, column=0, sticky="ew", padx=10, pady=5)
        frame.columnconfigure(0, weight=1)

        tk.Label(frame, text="Message to encrypt:").grid(row=0, column=0, sticky="w")
        self.message_entry = tk.Entry(frame)
        self.message_entry.insert(0, "Hello from user A to user B!")
        self.message_entry.grid(row=1, column=0, sticky="ew", padx=(0, 10))

        aes_btn = tk.Button(frame, text="Encrypt + Decrypt", command=self.run_aes_demo)
        aes_btn.grid(row=2, column=0, sticky="e", pady=4)

    def _build_output_area(self) -> None:
        frame = tk.LabelFrame(self.root, text="Output")
        frame.grid(row=4, column=0, sticky="nsew", padx=10, pady=5)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        self.output = ScrolledText(frame, height=18, state="disabled", wrap=tk.WORD)
        self.output.grid(row=0, column=0, sticky="nsew")

        clear_btn = tk.Button(frame, text="Clear Output", command=self.clear_output)
        clear_btn.grid(row=1, column=0, sticky="e", pady=4)

        self.root.rowconfigure(4, weight=1)

    def log(self, message: str) -> None:
        self.output.configure(state="normal")
        self.output.insert(tk.END, message + "\n")
        self.output.see(tk.END)
        self.output.configure(state="disabled")

    def clear_output(self) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", tk.END)
        self.output.configure(state="disabled")

    # ------------------------------------------------------------------
    # Core actions
    # ------------------------------------------------------------------
    def initialize_system(self) -> None:
        try:
            pool_size = int(self.pool_entry.get())
            keys_per_user = int(self.keys_entry.get())
        except ValueError:
            messagebox.showerror("Invalid input", "Pool size and keys per user must be integers.")
            return

        self.config = KeyDistributionConfig(KEY_POOL_SIZE=pool_size, KEYS_PER_USER=keys_per_user)
        self.server = KeyServer(config=self.config)
        self.server.generate_key_pool()
        self.data_service = DataProvisioningService(self.server)
        self.shared_service = SharedKeyService(self.server)

        self.log(f"Initialized system with pool size={pool_size}, keys per user={keys_per_user}.")
        self.log(f"Generated {pool_size} random keys.")

    def _require_server(self) -> bool:
        if self.server is None:
            messagebox.showwarning("Not initialized", "Please initialize the system first.")
            return False
        return True

    def register_user(self) -> None:
        if not self._require_server():
            return

        user_id = self.user_entry.get().strip()
        if not user_id:
            messagebox.showinfo("Missing user", "Enter a user ID before registering.")
            return

        user = self.server.register_user(user_id)
        self.log(f"User '{user.user_id}' registered with keys: {sorted(user.key_ids)}")
        self.user_entry.delete(0, tk.END)

    def list_users(self) -> None:
        if not self._require_server():
            return

        if not self.server.get_all_users():
            self.log("No users registered yet.")
            return

        self.log("=== Registered users ===")
        for user in sorted(self.server.get_all_users().values(), key=lambda u: u.user_id):
            self.log(f"{user.user_id}: keys {sorted(user.key_ids)}")

    def compute_shared_key(self) -> None:
        if not self._require_server() or self.shared_service is None:
            return

        user_a = self.user_a_entry.get().strip()
        user_b = self.user_b_entry.get().strip()

        if not user_a or not user_b:
            messagebox.showinfo("Missing users", "Enter both user IDs to compute a shared key.")
            return

        try:
            common_ids = self.shared_service.common_key_ids(user_a, user_b)
        except ValueError as exc:  # user not found
            messagebox.showerror("User error", str(exc))
            return

        if not common_ids:
            self.log(f"Users '{user_a}' and '{user_b}' share no keys.")
            return

        derived_hex = self.shared_service.compute_shared_key(user_a, user_b)
        self.log(f"Users '{user_a}' and '{user_b}' share key IDs: {sorted(common_ids)}")
        self.log(f"Derived shared key (hex): {derived_hex}")

    def run_aes_demo(self) -> None:
        if not self._require_server() or self.shared_service is None:
            return

        user_a = self.user_a_entry.get().strip()
        user_b = self.user_b_entry.get().strip()

        if not user_a or not user_b:
            messagebox.showinfo("Missing users", "Enter both user IDs first (in Shared Keys section).")
            return

        key_bytes = self.shared_service.compute_shared_key_bytes(user_a, user_b)
        if key_bytes is None:
            messagebox.showinfo("No shared key", "The selected users do not share any predistributed keys.")
            return

        message = self.message_entry.get().encode("utf-8")
        aes = AESCipher(key_bytes)
        nonce, ciphertext, tag = aes.encrypt(message)
        decrypted = aes.decrypt(nonce, ciphertext, tag)

        self.log(f"AES demo for '{user_a}' ↔ '{user_b}'")
        self.log(f"Nonce (hex):      {nonce.hex()}")
        self.log(f"Ciphertext (hex): {ciphertext.hex()}")
        self.log(f"Tag (hex):        {tag.hex()}")
        self.log(f"Decrypted text:   {decrypted.decode('utf-8')}")

    # ------------------------------------------------------------------
    def run(self) -> None:
        self.root.mainloop()


def launch_gui() -> None:
    gui = KeyDistributionGUI()
    gui.run()


if __name__ == "__main__":
    launch_gui()
