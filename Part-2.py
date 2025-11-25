# ---------- Crypto functions ----------
def derive_key(password: str, salt_b64: str):
    salt = base64.b64decode(salt_b64)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def new_salt_b64():
    return base64.b64encode(secrets.token_bytes(16)).decode()

def encrypt_bytes(key: bytes, plaintext: bytes):
    iv = secrets.token_bytes(16)  # 128-bit IV
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    return iv + ct  # prefix IV

def decrypt_bytes(key: bytes, blob: bytes):
    iv = blob[:16]
    ct = blob[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    dec = cipher.decryptor()
    pt = dec.update(ct) + dec.finalize()
    return pt
