# FUTURE_CS_03 – Secure File Sharing System 🔐

## 🧾 Project Overview

This project was developed as part of **Task 3** of the **Cybersecurity Internship under Future Interns**.

The goal was to build a secure file upload/download web portal using **AES encryption**, where users can:
- Upload a document
- Set a password to encrypt the file
- Generate a secure link to share
- Allow the recipient to decrypt and download the file using the password

This ensures **data security at rest and in transit**, making it useful for secure document sharing.

---

## 🧰 Tech Stack & Tools Used

- **Python Flask** – Backend Web Framework  
- **PyCryptodome** – AES Encryption library  
- **HTML / CSS** – Frontend UI  
- **Postman / Curl** – For API testing  
- **Git & GitHub** – Version Control  
- **Self-signed SSL Certificates** – To serve over HTTPS  

---

## 📁 Folder Structure
```
secure-file-sharing/
├── app.py                       # Main Flask application
├── crypto_utils.py              # AES encryption/decryption logic
├── key_manager.py               # Key generation & management
├── keys.db                      # SQLite database to store keys securely
├── requirements.txt             # Python dependencies
├── test_assets.py               # Test script for encryption/decryption
├── localhost.pem                # SSL certificate
├── localhost-key.pem            # SSL private key
├── localhost+2.pem              # Alternate SSL certificate
├── localhost+2-key.pem          # Alternate private key
├── __pycache__/                 # Compiled Python cache
│   ├── crypto_utils.cpython-313.pyc
│   └── key_manager.cpython-313.pyc
├── static/                      # Static assets (CSS, images, JS)
│   ├── crypto-bg.jpg
│   ├── lock-icon.svg
│   ├── style.css
│   └── wget-log
├── templates/                   # HTML templates for web interface
│   ├── index.html
│   ├── upload.html
│   ├── share.html
│   ├── password.html
│   ├── download.html
│   └── error.html
├── uploads/                     # Temporarily stores encrypted files
└── venv/                        # Python virtual environment (not included in repo)
```

---

## 🔐 Key Features

- AES-256 encryption to secure uploaded files  
- Secure password-based encryption/decryption  
- Self-signed HTTPS support (TLS)  
- Secure file download only with correct password  
- Simple & clean user interface  
- No plaintext storage of files or passwords  

---

## 💻 Getting Started – How to Run This Project Locally

To launch the Secure File Sharing System on your local machine:

```bash
# Step 1: Clone the repository
git clone https://github.com/Magnus7811/FUTURE_CS_03.git
cd FUTURE_CS_03

# Step 2: Set up a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Step 3: Install dependencies
pip install -r requirements.txt

# Step 4: Run the Flask app with SSL
python app.py
