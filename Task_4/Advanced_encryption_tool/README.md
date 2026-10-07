# 🛡️ AegisVault - Advanced Encryption Tool

AegisVault is a robust, production-grade desktop encryption tool built with Python, featuring streaming **AES-256-GCM** encryption, **scrypt 2-Factor key derivation**, tamper-evident binary chunking, atomic safe decryption, directory archiving, and a modern **Tkinter GUI** alongside a feature-complete **CLI**.

---

## ✨ Features

- **Streaming AES-256-GCM**: Files are processed in 1 MB chunks ($O(1)$ memory). Supports multi-GB files, databases, and videos without loading the file into RAM.
- **Tamper-Evident Chunking**: Nonces encode chunk indices and final-chunk flags. Reordering, truncation, or bit-flipping is immediately detected and rejected.
- **Two-Factor Keys (2FA)**: Key material derived from a password, an optional keyfile (USB token or key file), or both, stretched with `scrypt` (memory-hard, resistant to GPU brute-forcing).
- **Atomic / Safe Decryption**: Decryption writes to a temporary file and renames it ONLY after 100% of chunks verify successfully. A wrong password or corrupted byte will never corrupt your target output file.
- **Folder Support**: Archives full directory trees into `.tar.aev` archives on-the-fly and restores them upon decryption with built-in path-traversal (Tar-Slip) protection.
- **Usability Features**: Real-time password strength meter (entropy bit calculation), cryptographically secure password generator, progress bar, optional best-effort file wipe, and CLI support for automation.

---

## 🚀 Installation & Setup

1. **Clone or Download Project** into your workspace directory.
2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   *(Note: `tkinter` is built into standard Python distributions on Windows).*

---

## 💻 How to Run

### Option A: Launch Tkinter GUI (Desktop App)

Open VS Code terminal and run:
```bash
python aegisvault.py
```

### Option B: Use Command-Line Interface (CLI)

#### Encrypt a File or Folder:
```bash
# Encrypt a single file
python aegisvault.py enc document.pdf -p "MyStrongPassword123!"

# Encrypt a folder with a 2FA keyfile
python aegisvault.py enc myfolder -k usb.key -p "MyStrongPassword123!"

# Encrypt and best-effort wipe original source file
python aegisvault.py enc secret.docx -p "MyStrongPassword123!" --wipe
```

#### Decrypt a `.aev` File:
```bash
# Decrypt a file
python aegisvault.py dec document.pdf.aev -p "MyStrongPassword123!"

# Decrypt with keyfile
python aegisvault.py dec myfolder.tar.aev -k usb.key -p "MyStrongPassword123!"
```

---

## 🧪 Running Automated Tests

Run the full unit and integration test suite to verify file encryption, multi-MB streaming, folder archiving, tamper detection, and bad password handling:

```bash
python -m unittest test_aegisvault.py -v
```

---

## 🏛️ Technical Architecture (For Reports & Vivas)

1. **File Binary Format (`.aev`)**:
   - `Magic Header` (8 bytes): `AEGISV01`
   - `Scrypt Salt` (16 bytes)
   - `Chunks`:
     - `Nonce` (12 bytes): `4B Random Prefix + 7B Chunk Index + 1B Final Flag`
     - `Length` (4 bytes)
     - `Ciphertext + Tag` (Payload + 16-byte AES-GCM Tag)

2. **Authenticated Associated Data (AAD)**:
   Each chunk binds `struct.pack(">QB", chunk_index, is_final)` as AAD. This guarantees chunk order integrity and detects truncation attacks.

3. **Key Derivation (Scrypt)**:
   Key derived via `scrypt(password + keyfile_bytes, salt, N=16384, r=8, p=1)`. Memory hardness prevents GPU/ASIC parallel dictionary attacks.
