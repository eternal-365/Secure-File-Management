# gui_sfms.py
import os
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import secrets

# ---------- Config / storage ----------
DATA_DIR = os.path.abspath(".")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
FILES_FILE = os.path.join(DATA_DIR, "files.json")
ACCESS_FILE = os.path.join(DATA_DIR, "access_matrix.json")
STORAGE_DIR = os.path.join(DATA_DIR, "users")
os.makedirs(STORAGE_DIR, exist_ok=True)

# ---------- Helpers for JSON ----------
def load_json(path, default):
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump(default, f)
        return default.copy()
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default.copy()

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

# Initialize files if missing
users = load_json(USERS_FILE, {})
files = load_json(FILES_FILE, {})  # maps file_id -> metadata
access = load_json(ACCESS_FILE, {})  # maps file_id -> list of usernames with read access

# Create default ADMIN if missing
if "ADMIN" not in users:
    # create admin with password 'admin1'
    salt = secrets.token_bytes(16)
    admin_key = None
    def derive_key(password: str, salt_bytes: bytes):
        kdf = Scrypt(salt=salt_bytes, length=32, n=2**14, r=8, p=1)
        return kdf.derive(password.encode())
    admin_key = derive_key("admin1", salt)
    users["ADMIN"] = {
        "role": "admin",
        "salt": base64.b64encode(salt).decode(),
        "pwd_key": base64.b64encode(admin_key).decode()
    }
    save_json(USERS_FILE, users)
