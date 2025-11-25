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

# ---------- GUI ----------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure File Management (GUI Prototype)")
        self.geometry("820x520")
        self.resizable(False, False)
        self.current_user = None
        self.create_login_frame()

    def clear(self):
        for w in self.winfo_children():
            w.destroy()

    # ---------- Login/Register ----------
    def create_login_frame(self):
        self.clear()
        frm = ttk.Frame(self, padding=20)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Secure File Management", font=("TkDefaultFont", 16, "bold")).pack(pady=10)
        inner = ttk.Frame(frm)
        inner.pack(pady=10)

        ttk.Label(inner, text="Username:").grid(row=0, column=0, sticky="e")
        user_ent = ttk.Entry(inner)
        user_ent.grid(row=0, column=1, pady=5)

        ttk.Label(inner, text="Password:").grid(row=1, column=0, sticky="e")
        pass_ent = ttk.Entry(inner, show="*")
        pass_ent.grid(row=1, column=1, pady=5)

        def do_login():
            u = user_ent.get().strip()
            p = pass_ent.get().strip()
            ok, msg = verify_user(u, p)
            if ok:
                self.current_user = u
                messagebox.showinfo("Login", f"Welcome {u}")
                self.create_main_frame()
            else:
                messagebox.showerror("Login failed", msg)

        def do_register():
            u = user_ent.get().strip()
            p = pass_ent.get().strip()
            if not u or not p:
                messagebox.showerror("Register", "Enter username and password")
                return
            role = "user"
            # simple prompt for role if registering admin (only ADMIN can create admin)
            if u.upper() == "ADMIN":
                role = "admin"
            ok, msg = add_user(u, p, role)
            if ok:
                messagebox.showinfo("Registered", f"User {u} created. Now login.")
            else:
                messagebox.showerror("Register error", msg)

        ttk.Button(frm, text="Login", command=do_login).pack(side="left", padx=60, pady=20)
        ttk.Button(frm, text="Register", command=do_register).pack(side="left", padx=10, pady=20)

        ttk.Label(frm, text="Default admin: ADMIN / admin1", foreground="gray").pack(side="bottom", pady=8)

    # ---------- Main ----------
    def create_main_frame(self):
        self.clear()
        top = ttk.Frame(self, padding=6)
        top.pack(fill="x")
        ttk.Label(top, text=f"Logged in as: {self.current_user}", font=("TkDefaultFont", 12)).pack(side="left")

        ttk.Button(top, text="Logout", command=self.logout).pack(side="right", padx=6)

        # Tabs
        tabs = ttk.Notebook(self)
        tabs.pack(fill="both", expand=True, padx=10, pady=10)

        # Upload tab
        tab_upload = ttk.Frame(tabs)
        tabs.add(tab_upload, text="Upload File")
        self.build_upload_tab(tab_upload)

        # My files tab
        tab_myfiles = ttk.Frame(tabs)
        tabs.add(tab_myfiles, text="My Files")
        self.build_myfiles_tab(tab_myfiles)

        # Shared with me
        tab_shared = ttk.Frame(tabs)
        tabs.add(tab_shared, text="Shared With Me")
        self.build_shared_tab(tab_shared)

        # Admin tab (if admin)
        role = users.get(self.current_user, {}).get("role", "user")
        if role == "admin":
            tab_admin = ttk.Frame(tabs)
            tabs.add(tab_admin, text="Admin")
            self.build_admin_tab(tab_admin)

    def logout(self):
        self.current_user = None
        self.create_login_frame()

    # ---------- Upload tab builder ----------
    def build_upload_tab(self, parent):
        frm = ttk.Frame(parent, padding=12)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Select file to upload and encrypt:", font=("TkDefaultFont", 11)).pack(anchor="w")
        path_var = tk.StringVar()
        ttk.Entry(frm, textvariable=path_var, width=70).pack(pady=6)
        def browse():
            p = filedialog.askopenfilename()
            if p:
                path_var.set(p)
        ttk.Button(frm, text="Browse", command=browse).pack(pady=4)

        ttk.Label(frm, text="Encryption password for this file (share this with recipients):").pack(anchor="w", pady=(10,0))
        pwd_ent = ttk.Entry(frm, show="*")
        pwd_ent.pack(pady=4)

        def do_upload():
            p = path_var.get().strip()
            pwd = pwd_ent.get().strip()
            if not p or not os.path.exists(p):
                messagebox.showerror("Upload", "Choose a valid file")
                return
            if not pwd:
                messagebox.showerror("Upload", "Provide a password for file encryption")
                return
            with open(p, "rb") as f:
                data = f.read()
            fid, _ = store_encrypted_file(self.current_user, p, data, pwd)
            messagebox.showinfo("Upload", f"Uploaded and encrypted as id: {fid}")
            # refresh lists
            self.create_main_frame()

        ttk.Button(frm, text="Upload & Encrypt", command=do_upload).pack(pady=10)

    # ---------- My files tab ----------
    def build_myfiles_tab(self, parent):
        frm = ttk.Frame(parent, padding=8)
        frm.pack(fill="both", expand=True)
        cols = ("ID","Name","Size","Owner")
        tree = ttk.Treeview(frm, columns=cols, show="headings", height=14)
        for c in cols:
            tree.heading(c, text=c)
            tree.column(c, width=150)
        tree.pack(side="left", fill="y", padx=(0,6))
        scrollbar = ttk.Scrollbar(frm, orient="vertical", command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="left", fill="y")

        # fill
        for fid, meta in files.items():
            if meta["owner"] == self.current_user:
                tree.insert("", "end", iid=fid, values=(fid, meta["orig_name"], meta["size"], meta["owner"]))

        # right panel
        rpanel = ttk.Frame(frm)
        rpanel.pack(fill="both", expand=True, padx=6)
        ttk.Label(rpanel, text="Selected file operations:").pack(anchor="w")
        def on_download():
            sel = tree.selection()
            if not sel:
                messagebox.showerror("Download","Select a file")
                return
            fid = sel[0]
            pwd = simpledialog.askstring("File Password", "Enter encryption password for this file:", show="*")
            if pwd is None:
                return
            ok, res = retrieve_encrypted_file(fid, pwd)
            if not ok:
                messagebox.showerror("Error", res)
                return
            # ask where to save
            save_to = filedialog.asksaveasfilename(initialfile=files[fid]["orig_name"])
            if not save_to:
                return
            with open(save_to, "wb") as out:
                out.write(res)
            messagebox.showinfo("Downloaded", f"Saved to {save_to}")

        def on_share():
            sel = tree.selection()
            if not sel:
                messagebox.showerror("Share","Select a file")
                return
            fid = sel[0]
            target = simpledialog.askstring("Share", "Enter username to share with (must exist):")
            if not target:
                return
            if target not in users:
                messagebox.showerror("Share", "No such user")
                return
            access_list = access.get(fid, [])
            if target in access_list:
                messagebox.showinfo("Share","User already has access")
                return
            access_list.append(target)
            access[fid] = access_list
            save_json(ACCESS_FILE, access)
            messagebox.showinfo("Share", f"Shared {files[fid]['orig_name']} with {target}")

        ttk.Button(rpanel, text="Download (Decrypt)", command=on_download).pack(fill="x", pady=4)
        ttk.Button(rpanel, text="Share with user", command=on_share).pack(fill="x", pady=4)

    # ---------- Shared with me tab ----------
    def build_shared_tab(self, parent):
        frm = ttk.Frame(parent, padding=8)
        frm.pack(fill="both", expand=True)
        cols = ("ID","Name","Size","Owner")
        tree = ttk.Treeview(frm, columns=cols, show="headings", height=16)
        for c in cols:
            tree.heading(c, text=c)
            tree.column(c, width=150)
        tree.pack(side="left", fill="both", padx=(0,6))
        scrollbar = ttk.Scrollbar(frm, orient="vertical", command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="left", fill="y")

        # fill with files that include current_user in access list (but not owner)
        for fid, meta in files.items():
            acl = access.get(fid, [])
            if self.current_user in acl and meta["owner"] != self.current_user:
                tree.insert("", "end", iid=fid, values=(fid, meta["orig_name"], meta["size"], meta["owner"]))

        rpanel = ttk.Frame(frm)
        rpanel.pack(fill="both", expand=True, padx=6)

        def on_download_shared():
            sel = tree.selection()
            if not sel:
                messagebox.showerror("Download","Select a file")
                return
            fid = sel[0]
            pwd = simpledialog.askstring("File Password", f"Enter encryption password (owner {files[fid]['owner']} set):", show="*")
            if pwd is None:
                return
            ok, res = retrieve_encrypted_file(fid, pwd)
            if not ok:
                messagebox.showerror("Error", res)
                return
            save_to = filedialog.asksaveasfilename(initialfile=files[fid]["orig_name"])
            if not save_to:
                return
            with open(save_to, "wb") as out:
                out.write(res)
            messagebox.showinfo("Downloaded", f"Saved to {save_to}")

        ttk.Button(rpanel, text="Download Shared File", command=on_download_shared).pack(fill="x", pady=4)

    # ---------- Admin tab ----------
    def build_admin_tab(self, parent):
        frm = ttk.Frame(parent, padding=8)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Admin Panel", font=("TkDefaultFont", 12, "bold")).pack(anchor="w")
        # list users
        ulist = tk.Listbox(frm, height=8)
        for uname in users.keys():
            ulist.insert("end", f"{uname} ({users[uname].get('role','user')})")
        ulist.pack(fill="x", pady=6)
        def del_user():
            sel = ulist.curselection()
            if not sel:
                messagebox.showerror("Delete", "Select a user")
                return
            entry = ulist.get(sel[0]).split()[0]
            if entry == "ADMIN":
                messagebox.showerror("Delete", "Cannot delete ADMIN")
                return
            confirm = messagebox.askyesno("Confirm", f"Delete user {entry} and their files?")
            if not confirm:
                return
            # remove user entries
            users.pop(entry, None)
            # remove files owned
            to_remove = [fid for fid, m in files.items() if m["owner"] == entry]
            for fid in to_remove:
                # delete file from storage
                try:
                    os.remove(os.path.join(STORAGE_DIR, files[fid]["storage_name"]))
                except Exception:
                    pass
                files.pop(fid, None)
                access.pop(fid, None)
            save_json(USERS_FILE, users)
            save_json(FILES_FILE, files)
            save_json(ACCESS_FILE, access)
            messagebox.showinfo("Deleted", f"User {entry} removed")
            self.create_main_frame()

        def add_user_admin():
            uname = simpledialog.askstring("New user", "Username:")
            pwd = simpledialog.askstring("Password", "Password:", show="*")
            role = simpledialog.askstring("Role", "Role (user/viewer/admin):", initialvalue="user")
            if not uname or not pwd:
                return
            ok, msg = add_user(uname, pwd, role)
            if ok:
                messagebox.showinfo("Added", f"User {uname} added")
                self.create_main_frame()
            else:
                messagebox.showerror("Error", msg)

        ttk.Button(frm, text="Add User", command=add_user_admin).pack(side="left", padx=6, pady=6)
        ttk.Button(frm, text="Delete Selected User", command=del_user).pack(side="left", padx=6, pady=6)


if __name__ == "__main__":
    app = App()
    app.mainloop()
