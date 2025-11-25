# ---------- File operations ----------
def add_user(username: str, password: str, role="user"):
    if username in users:
        return False, "User already exists"
    salt_b64 = new_salt_b64()
    kdf = Scrypt(salt=base64.b64decode(salt_b64), length=32, n=2**14, r=8, p=1)
    pwd_key = kdf.derive(password.encode())
    users[username] = {
        "role": role,
        "salt": salt_b64,
        "pwd_key": base64.b64encode(pwd_key).decode()
    }
    save_json(USERS_FILE, users)
    return True, "User registered"

def verify_user(username: str, password: str):
    if username not in users:
        return False, "User not found"
    entry = users[username]
    salt_b64 = entry["salt"]
    try:
        derived = derive_key(password, salt_b64)
        expected = base64.b64decode(entry["pwd_key"])
        if derived == expected:
            return True, "OK"
        else:
            return False, "Incorrect password"
    except Exception as e:
        return False, "Verification error"

def store_encrypted_file(owner: str, filename: str, plaintext: bytes, password_for_file: str):
    # derive key from password_for_file
    salt_file = secrets.token_bytes(16)
    kdf = Scrypt(salt=salt_file, length=32, n=2**14, r=8, p=1)
    key = kdf.derive(password_for_file.encode())
    blob = encrypt_bytes(key, plaintext)
    # file id
    fid = secrets.token_hex(8)
    save_name = f"{owner}_{fid}_{os.path.basename(filename)}.enc"
    path = os.path.join(STORAGE_DIR, save_name)
    with open(path, "wb") as f:
        f.write(salt_file + blob)  # store salt + iv+ct
    files[fid] = {
        "owner": owner,
        "orig_name": os.path.basename(filename),
        "storage_name": save_name,
        "size": len(plaintext)
    }
    access[fid] = [owner]  # owner has access by default
    save_json(FILES_FILE, files)
    save_json(ACCESS_FILE, access)
    return fid, path

def retrieve_encrypted_file(fid: str, password_for_file: str):
    if fid not in files:
        return False, "file id not found"
    meta = files[fid]
    path = os.path.join(STORAGE_DIR, meta["storage_name"])
    if not os.path.exists(path):
        return False, "stored file missing"
    with open(path, "rb") as f:
        data = f.read()
    salt_file = data[:16]
    blob = data[16:]
    # derive key
    kdf = Scrypt(salt=salt_file, length=32, n=2**14, r=8, p=1)
    try:
        key = kdf.derive(password_for_file.encode())
        pt = decrypt_bytes(key, blob)
        return True, pt
    except Exception as e:
        return False, f"Decryption failed: {e}"
