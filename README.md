# Secure File Management System

A Python-based secure file management system with user roles (Admin, User, Viewer), AES encryption for file confidentiality, password hashing using Scrypt, and role-based access control.

## Features

1. User Roles:  
        Admin: Manage users, list files, remove accounts.  
        User: Upload, encrypt, share, and download files.  
        Viewer:View files shared with them (read-only).  

2. Security:  
        Passwords are hashed using `Scrypt`.  
        Files are encrypted using `AES` (CFB8 mode).  
        Role-based access to restrict operations.  

3. File Sharing:  
        Users can share files with others (read-only access).  
        Admin can view all file-sharing relationships.  

 ## Setup Instructions

1. Install Requirements   
        Ensure you have Python 3.x and install `cryptography` if not already installed:  

        ```bash
        pip install cryptography
   
2. Run the System  
        python secure_file_system.py

3. Default Admin Login  
        Username: ADMIN  
        Password: admin1  
        (Admin account is automatically created on first run if it doesn’t exist.)  

 ## Functional Overview
 
1. Registration & Login  
        Users can register as either User or Viewer.  
        Secure password storage using Scrypt hashing.  

2. File Operations  
        Upload: Users can encrypt and upload files with a password.  
        Download: Accessible only to owners or users with shared read access.  
        Share: Users can share files with other registered users (read-only).  

3. Encryption Details  
        Key Derivation: Scrypt  
        Encryption Algorithm: AES (CFB8 mode)  

## Example Usage

1. User uploads a file:  
        Enters file content and password for encryption.  
        File saved as username_filename.enc in the users/ directory.  

2. Sharing a file:  
        Owner selects a target user to share the file.  
        Target user can only view (download) the file with correct decryption password.  

3. Admin tasks:  
        View all user accounts and their files.  
        Delete users and their files.  
        Register new users or viewers.  

4. Security Considerations  
        Avoid using weak passwords for file encryption.  
        Sharing encrypted files still requires the receiver to know the encryption password.  


