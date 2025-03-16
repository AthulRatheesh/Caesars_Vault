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

## 📦 Set Up a Virtual Environment (Recommended)

python -m venv env
source env/bin/activate      # Windows: env\Scripts\activate

## 📌 Install Dependencies

pip install -r requirements.txt

## 🗄 Initialize the Database

python Database.py

### 🎯 Usage

## 🏁 Run the Application

python Locker.py

## 🔐 Authentication Workflow

- Login using your email & password.
- OTP Verification – An OTP is sent to your registered email.
- Access File Encryption & Folder Locking.

## 🛡️ File Encryption & Decryption

✔ Encrypt a File:

    - Select a file → Enter a password → Encrypt.
    - Generates .enc file (AES-256 encrypted).

✔ Decrypt a File:

    - Select an encrypted file → Enter the same password → Decrypt.

## 🔏 Folder Locking & Unlocking

✔ Lock a Folder: 

    - Select a directory, set a password, and secure its contents.
    
✔ Unlock a Folder: 

    - Provide the correct password to restore access.

## 🛡️ Security Measures

✔ Passwords are securely hashed using SHA-256.

✔ OTP authentication via email ensures 2FA security.

✔ AES-256 encryption provides industry-standard protection.

✔ Unauthorized access detection via logs and user tracking.
