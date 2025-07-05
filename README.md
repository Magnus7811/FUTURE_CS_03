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

secure-file-sharing/
├── app.py # Main Flask application
├── crypto_utils.py # AES encryption/decryption functions
├── key_manager.py # Key generation and storage logic
├── keys.db # SQLite DB storing file keys securely
├── requirements.txt # Python dependencies
├── static/ # CSS or JS files (optional styling/scripts)
├── templates/ # HTML templates (index, upload, decrypt)
├── uploads/ # Stores encrypted files temporarily
├── test_assets.py # Testing logic for encryption/decryption
├── venv/ # Virtual environment
├── pycache/ # Compiled Python cache
├── localhost.pem # SSL certificate (HTTPS)
├── localhost-key.pem # SSL private key
├── localhost+2.pem # Alternate SSL cert (multi-domain)
├── localhost+2-key.pem # Alternate private key


---

## 🔐 Key Features

- AES-256 encryption to secure uploaded files  
- Secure password-based encryption/decryption  
- Self-signed HTTPS support (TLS)  
- Secure file download only with correct password  
- Simple & clean user interface  
- No plaintext storage of files or passwords  

---

## 🚀 How to Run the Project Locally

### 1. Clone the Repository

```bash
git clone https://github.com/Magnus7811/FUTURE_CS_03.git
cd FUTURE_CS_03

### 2. Create & Activate Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

### 3. Install Required Packages

```bash
pip install -r requirements.txt

### 4. Run Flask Application with SSL

```bash
python app.py

### Open in browser:
🔗 https://localhost:5000

    ⚠️ Accept the browser’s SSL warning (self-signed cert)
