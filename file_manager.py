import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64

USER_DIR = "./users/"
if not os.path.exists(USER_DIR):
    os.makedirs(USER_DIR)

SALT = b'secure_salt'

# Predefined admin details
PREDEFINED_ADMIN = {
    'username': 'ADMIN',
    'password': 'admin1',
    'role': 'Admin',
    'files': {},
    'permissions': {}
}

# Setup initial admin if not present
def setup_admin():
    admin_path = os.path.join(USER_DIR, f"{PREDEFINED_ADMIN['username']}.json")
    if not os.path.exists(admin_path):
        PREDEFINED_ADMIN['password'] = hash_password(PREDEFINED_ADMIN['password'])
        with open(admin_path, 'w') as f:
            json.dump(PREDEFINED_ADMIN, f)
        print("Predefined Admin created.")

# Password Hashing
def hash_password(password):
    kdf = Scrypt(salt=SALT, length=32, n=2**14, r=8, p=1, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password.encode())).decode()

def verify_password(password, hashed_password):
    try:
        kdf = Scrypt(salt=SALT, length=32, n=2**14, r=8, p=1, backend=default_backend())
        kdf.verify(password.encode(), base64.urlsafe_b64decode(hashed_password))
        return True
    except:
        return False

# Encryption & Decryption
def derive_key(password):
    kdf = Scrypt(salt=SALT, length=32, n=2**14, r=8, p=1, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_file(content, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB8(key[:16]), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(content) + encryptor.finalize()

def decrypt_file(encrypted_content, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB8(key[:16]), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_content) + decryptor.finalize()

# Registration & Login
def register_user():
    username = input("Enter username: ")
    role = input("Enter role (User/Viewer): ").capitalize()
    if role not in ['User', 'Viewer']:
        print("Invalid role. Must be 'User' or 'Viewer'.")
        return

    password = input("Enter password: ")
    user_path = os.path.join(USER_DIR, f"{username}.json")

    if os.path.exists(user_path):
        print("User already exists.")
        return

    hashed_password = hash_password(password)
    user_data = {
        'username': username,
        'password': hashed_password,
        'role': role,
        'files': {},
        'permissions': {}
    }

    with open(user_path, 'w') as f:
        json.dump(user_data, f)
    print(f"{role} '{username}' registered successfully.")

def login_user():
    username = input("Enter username: ")
    password = input("Enter password: ")
    user_path = os.path.join(USER_DIR, f"{username}.json")

    if not os.path.exists(user_path):
        print("User does not exist.")
        return None

    with open(user_path, 'r') as f:
        user_data = json.load(f)

    if verify_password(password, user_data['password']):
        print(f"User {username} logged in successfully as {user_data['role']}.")
        return user_data
    else:
        print("Invalid credentials.")
        return None

# File Operations
def upload_file(user):
    filename = input("Enter the filename to upload: ")
    content = input("Enter file content: ")
    password = input("Enter password to encrypt the file: ")
    
    key = derive_key(password)
    encrypted_content = encrypt_file(content.encode(), key)
    
    file_path = os.path.join(USER_DIR, f"{user['username']}_{filename}.enc")
    with open(file_path, 'wb') as f:
        f.write(encrypted_content)
    
    user['files'][filename] = file_path
    user['permissions'][filename] = {'owner': user['username'], 'permissions': ['read', 'write']}
    save_user_data(user)
    print(f"File '{filename}' uploaded and encrypted successfully.")

def download_file(user):
    filename = input("Enter the filename to download: ")
    password = input("Enter password to decrypt the file: ")
    
    user_data = load_user_data(user['username'])
    
    # Determine if the user owns the file or only has shared access
    file_path = None
    if filename in user_data['files']:
        # User owns the file
        file_path = user_data['files'][filename]
    elif filename in user_data['permissions'] and 'read' in user_data['permissions'][filename]['permissions']:
        # User has been granted shared access
        file_owner = user_data['permissions'][filename]['owner']
        file_path = os.path.join(USER_DIR, f"{file_owner}_{filename}.enc")
    else:
        print("File not found or you do not have permission to access this file.")
        return
    
    # Proceed to decrypt the file with the provided password
    try:
        with open(file_path, 'rb') as f:
            encrypted_content = f.read()
        
        key = derive_key(password)
        content = decrypt_file(encrypted_content, key).decode()
        print(f"File '{filename}' content:\n{content}")
    except Exception as e:
        print("Decryption failed. Incorrect password or permission issue.")

def share_file(user):
    filename = input("Enter the filename to share: ")
    target_user = input("Enter the username to share the file with: ")
    
    user_data = load_user_data(user['username'])
    target_user_data = load_user_data(target_user)

    # Check if target user exists
    if target_user_data is None:
        print("Invalid user.")
        return

    # Check if the file exists in the user's files
    if filename not in user_data['files']:
        print("File not found.")
        return
    
    # Add permission in the target user's data
    if 'permissions' not in target_user_data:
        target_user_data['permissions'] = {}

    # Update shared file permissions
    target_user_data['permissions'][filename] = {
        'owner': user['username'],
        'permissions': ['read']  # Limit to read for shared files
    }
    
    # Save the updated target user's data
    save_user_data(target_user_data)
    print(f"File '{filename}' shared with {target_user}.")

# Admin Functions
def manage_users():
    while True:
        print("\nManage Users")
        print("1. Register User/Viewer")
        print("2. Remove User/Viewer")
        print("3. List Users and Viewers")
        print("4. Back to Main Menu")
        
        choice = input("Enter choice: ")
        if choice == '1':
            register_user()
        elif choice == '2':
            username = input("Enter the username to remove: ")
            user_path = os.path.join(USER_DIR, f"{username}.json")
            if os.path.exists(user_path):
                # Delete user's files
                for file in os.listdir(USER_DIR):
                    if file.startswith(f"{username}_") and file.endswith('.enc'):
                        os.remove(os.path.join(USER_DIR, file))
                os.remove(user_path)
                print(f"User '{username}' and all associated files removed successfully.")
            else:
                print("User not found.")
        elif choice == '3':
            list_users_and_viewers()
        elif choice == '4':
            break
        else:
            print("Invalid choice.")

def list_files():
    print("\nFiles:")
    for user_file in os.listdir(USER_DIR):
        if user_file.endswith('.json'):
            user_data = load_user_data(user_file.replace('.json', ''))
            username = user_data['username']
            role = user_data['role']
            files = user_data.get('files', {})

            # Exclude admin and users with no files or role as 'Viewer'
            if role != 'Admin' and files and role == 'User':
                print(f"Username: {username} (Role: {role})")
                for filename, path in files.items():
                    owner = user_data['permissions'][filename]['owner']
                    shared_with = [u_data['username'] for u_data in get_shared_users(filename)]
                    print(f"  - {filename}:")
                    print(f"    Owner: {owner}")
                    print(f"    Shared with: {shared_with if shared_with else 'None'}")

def list_users_and_viewers():
    print("\nUsers and Viewers:")
    users, viewers = [], []
    
    # Separate users and viewers, excluding admin
    for user_file in os.listdir(USER_DIR):
        if user_file.endswith('.json'):
            user_data = load_user_data(user_file.replace('.json', ''))
            if user_data['role'] == 'User' and user_data['username'] != 'ADMIN':
                users.append(user_data)
            elif user_data['role'] == 'Viewer' and user_data['username'] != 'ADMIN':
                viewers.append(user_data)
    
    # Display users first, then viewers
    for user in users:
        print(f"Username: {user['username']}, Role: {user['role']}")
    for viewer in viewers:
        print(f"Username: {viewer['username']}, Role: {viewer['role']}")

def get_shared_users(filename):
    shared_users = []
    for user_file in os.listdir(USER_DIR):
        if user_file.endswith('.json'):
            user_data = load_user_data(user_file.replace('.json', ''))
            if filename in user_data.get('permissions', {}) and user_data['permissions'][filename]['owner'] != user_data['username']:
                shared_users.append(user_data)
    return shared_users

# Load and Save User Data
def load_user_data(username):
    user_path = os.path.join(USER_DIR, f"{username}.json")
    if os.path.exists(user_path):
        with open(user_path, 'r') as f:
            return json.load(f)
    return None

def save_user_data(user_data):
    user_path = os.path.join(USER_DIR, f"{user_data['username']}.json")
    with open(user_path, 'w') as f:
        json.dump(user_data, f)

# Main Function
def main():
    setup_admin()
    logged_in_user = None
    
    while True:
        print("\nSecure File Management System")
        print("1. Login")
        print("2. Register")
        print("3. Exit")

        choice = input("Enter choice: ")
        if choice == '1':
            logged_in_user = login_user()
            if logged_in_user:
                if logged_in_user['role'] == 'Admin':
                    while True:
                        print("\nAdmin Menu")
                        print("1. List Files")
                        print("2. Manage Users")
                        print("3. Logout")

                        admin_choice = input("Enter choice: ")
                        if admin_choice == '1':
                            list_files()
                        elif admin_choice == '2':
                            manage_users()
                        elif admin_choice == '3':
                            logged_in_user = None
                            break
                        else:
                            print("Invalid choice.")
                elif logged_in_user['role'] == 'Viewer':
                    while True:
                        print("\nViewer Menu")
                        print("1. Download File")
                        print("2. Logout")

                        viewer_choice = input("Enter choice: ")
                        if viewer_choice == '1':
                            download_file(logged_in_user)
                        elif viewer_choice == '2':
                            logged_in_user = None
                            break
                        else:
                            print("Invalid choice.")
                elif logged_in_user['role'] == 'User':
                    while True:
                        print("\nUser Menu")
                        print("1. Upload File")
                        print("2. Download File")
                        print("3. Share File")
                        print("4. Logout")

                        user_choice = input("Enter choice: ")
                        if user_choice == '1':
                            upload_file(logged_in_user)
                        elif user_choice == '2':
                            download_file(logged_in_user)
                        elif user_choice == '3':
                            share_file(logged_in_user)
                        elif user_choice == '4':
                            logged_in_user = None
                            break
                        else:
                            print("Invalid choice.")
        elif choice == '2':
            register_user()
        elif choice == '3':
            print("Exiting the system.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()

