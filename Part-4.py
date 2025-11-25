
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
