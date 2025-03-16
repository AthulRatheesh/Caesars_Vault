# FileEncryptor  
This is a file encrypting program made using Python.  

## 📌 Overview  
The **FileEncryptor** is a powerful security tool that provides **AES-256 encryption**, **Multi-Factor Authentication (MFA)**, and **Role-Based Access Control (RBAC)** to ensure maximum data protection. It enables users to **encrypt, decrypt, lock, and unlock files & folders** with a seamless **GUI-based experience**.

---

## ✨ Key Features  
- 🔐 **AES-256 Encryption & Decryption** – Ensures confidentiality of sensitive files.  
- 🔑 **Multi-Factor Authentication (MFA)** – OTP-based verification for additional security.  
- 👥 **Role-Based Access Control (RBAC)** – Three access levels: **Admin, User, Guest**.  
- 📂 **File & Folder Security** – Lock entire folders with a password-based mechanism.  
- 🛡️ **File Integrity Verification** – Detect unauthorized modifications using **SHA-256 hashing**.  
- 🔍 **Intrusion Detection & Logs** – Tracks unauthorized access attempts.  

---

## 🛠️ Tech Stack  

| Technology | Purpose |
|------------|---------|
| **Python** | Core programming language |
| **PyQt5** | Graphical User Interface (GUI) |
| **pycryptodome** | AES-256 encryption & decryption |
| **pyotp** | OTP-based Multi-Factor Authentication |
| **SQLAlchemy** | Database ORM for SQLite |
| **hashlib** | SHA-256 hashing for file integrity verification |
| **smtplib** | Email-based OTP delivery |

---

## 🚀 Installation & Setup  

### 🔧 **Prerequisites**  
Ensure you have **Python 3.8+** installed.  

### 📦 Set Up a Virtual Environment (Recommended)

- python -m venv venv
- source venv/bin/activate       ( Windows: venv\Scripts\activate )

### 📌 Install Dependencies

pip install -r requirements.txt

### 🗄 Initialize the Database

python Database.py

### 🏁 Run the Application

python Locker.py

---

## 🔐 Authentication Workflow

### Step 1: User Login

- The user enters email and password.
- The system verifies the hashed password stored in the database.

### Step 2: OTP Verification

- If the password is correct, an OTP is generated using mfa_secret and sent to the user’s registered email.
- The user enters the OTP into the system.
- If the OTP is valid (within 120 seconds), the login is successful, and the user gains access.

---

## 🔓 Post-Verification: File & Folder Security Operations

After successful OTP verification, the user is directed to the main dashboard, where they can perform the following operations:

### 🛡️ File Encryption & Decryption

✔ Encrypt a File:

- Select a file → Enter a password → Encrypt.
- Generates .enc file (AES-256 encrypted).

✔ Decrypt a File:

- Select an encrypted file → Enter the same password → Decrypt.

### 🔏 Folder Locking & Unlocking

✔ Lock a Folder: 

- Select a directory, set a password, and secure its contents.
    
✔ Unlock a Folder: 

- Provide the correct password to restore access.

---

## 🔑 Multi-Factor Authentication (MFA) Process

This system uses Time-Based One-Time Passwords (TOTP) for Multi-Factor Authentication (MFA). Each user is assigned a unique MFA secret key, which is stored securely in the database. The secret key is used to generate temporary OTPs for login verification.

### 📌 Step 1: User Registration & MFA Secret Generation

- User enters email, password, and role (Admin, User, or Guest) during registration.
- A random MFA secret key (mfa_secret) is generated for the user.
- The password is hashed using SHA-256 before storage.
- All credentials (email, hashed password, role, MFA secret) are stored in the SQLite database.

### 📌 Step 2: Generating OTP for Login

- When a user attempts to log in, the system retrieves the stored mfa_secret.
- A 6-digit OTP is generated and sent via email.
- The OTP is valid for 120 seconds.

### 📌 Step 3: OTP Verification

- The user enters the OTP received via email.
- The system verifies the OTP against the one generated using mfa_secret.

---

## 🛡️ Security Measures

✔ Passwords are securely hashed using SHA-256.

✔ OTP authentication via email ensures 2FA security.

✔ AES-256 encryption provides industry-standard protection.

✔ Unauthorized access detection via logs and user tracking.

---

## 📜 License

This project is licensed under the MIT License.
