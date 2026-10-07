import os
import sys
import math
import secrets
import string
import struct
import tarfile
import tempfile
import argparse
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AegisVault File Specification Version 1
# Magic Header: 8 bytes
MAGIC_HEADER = b"AEGISV01"

# Parameters
SALT_SIZE = 16          # 128-bit salt for scrypt
CHUNK_SIZE = 1024 * 1024  # 1 MB chunk payload size
NONCE_SIZE = 12         # 96-bit AES-GCM nonce
TAG_SIZE = 16           # 128-bit GCM authentication tag
KEY_LEN = 32            # 256-bit AES key

# Scrypt parameters
SCRYPT_N = 2**14        # CPU/Memory cost parameter (16384)
SCRYPT_R = 8            # Block size parameter
SCRYPT_P = 1            # Parallelization parameter

def derive_key(password: str, keyfile_bytes: bytes, salt: bytes) -> bytes:
    """
    Derives a 256-bit key using scrypt from a password and optional keyfile bytes.
    Combines password + keyfile bytes as secret material.
    """
    secret = password.encode('utf-8') + (keyfile_bytes if keyfile_bytes else b'')
    kdf = Scrypt(
        salt=salt,
        length=KEY_LEN,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P
    )
    return kdf.derive(secret)

def wipe_file(filepath: str):
    """
    Best-effort secure deletion by overwriting file content with zeroes, ones, and random bytes
    before unlinking. Note: SSD wear leveling & copy-on-write filesystems can retain physical data.
    """
    if not os.path.isfile(filepath):
        return
    file_size = os.path.getsize(filepath)
    if file_size > 0:
        try:
            with open(filepath, "r+b") as f:
                # Pass 1: Zeroes
                f.seek(0)
                f.write(b'\x00' * file_size)
                f.flush()
                # Pass 2: Ones
                f.seek(0)
                f.write(b'\xFF' * file_size)
                f.flush()
                # Pass 3: Random
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
        except Exception:
            pass
    os.remove(filepath)

def encrypt_stream(in_stream, out_file, password: str, keyfile_bytes: bytes = None, progress_callback=None, total_size=None):
    """
    Encrypts bytes from in_stream into out_file using AES-256-GCM chunked streaming.
    """
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, keyfile_bytes, salt)
    aesgcm = AESGCM(key)

    # Write header: Magic (8B) + Salt (16B)
    out_file.write(MAGIC_HEADER)
    out_file.write(salt)

    base_iv = secrets.token_bytes(4) # 4 random prefix bytes for nonce
    chunk_index = 0
    bytes_processed = 0

    while True:
        chunk = in_stream.read(CHUNK_SIZE)
        if not chunk and chunk_index > 0:
            # Reached EOF on previous loop iteration if total file was exact multiple of CHUNK_SIZE
            break

        # Peek to see if this is the final chunk
        next_byte = in_stream.read(1)
        is_final = 1 if len(next_byte) == 0 else 0
        if not is_final:
            # Put back the peeked byte by chaining it with future reads
            chunk = chunk + next_byte + in_stream.read(CHUNK_SIZE - 1)
            # Peek again after full read
            peek = in_stream.read(1)
            is_final = 1 if len(peek) == 0 else 0
            if not is_final:
                # Put back peek byte for next loop
                in_stream = ChunkReaderWithPeek(in_stream, peek)

        # Build 12-byte Nonce: 4B base_iv + 7B chunk_index (big endian) + 1B is_final
        # Limit max chunks to 2^56 (~72 Petabytes)
        chunk_idx_bytes = chunk_index.to_bytes(7, byteorder='big')
        flag_byte = bytes([is_final])
        nonce = base_iv + chunk_idx_bytes + flag_byte

        # AAD: Authenticated Associated Data binds chunk index & is_final flag
        aad = struct.pack(">QB", chunk_index, is_final)

        ciphertext = aesgcm.encrypt(nonce, chunk, aad)

        # Write chunk record: Nonce (12B) + Length (4B) + Ciphertext (includes 16B tag)
        chunk_len = len(ciphertext)
        out_file.write(nonce)
        out_file.write(struct.pack(">I", chunk_len))
        out_file.write(ciphertext)

        bytes_processed += len(chunk)
        chunk_index += 1

        if progress_callback and total_size and total_size > 0:
            progress_callback(min(bytes_processed / total_size, 1.0))

        if is_final:
            break

class ChunkReaderWithPeek:
    def __init__(self, stream, peek_byte):
        self.stream = stream
        self.peek_byte = peek_byte

    def read(self, size=-1):
        if self.peek_byte is not None:
            first = self.peek_byte
            self.peek_byte = None
            if size == 1:
                return first
            rest = self.stream.read(size - 1 if size > 0 else -1)
            return first + rest
        return self.stream.read(size)

def decrypt_stream(in_file, out_stream, password: str, keyfile_bytes: bytes = None, progress_callback=None, total_size=None):
    """
    Decrypts AegisVault stream from in_file into out_stream.
    Raises ValueError on tampering, wrong password, or invalid format.
    """
    header = in_file.read(len(MAGIC_HEADER))
    if header != MAGIC_HEADER:
        raise ValueError("Invalid file format: AegisVault magic header missing or corrupt.")

    salt = in_file.read(SALT_SIZE)
    if len(salt) != SALT_SIZE:
        raise ValueError("Truncated file header: Salt missing.")

    key = derive_key(password, keyfile_bytes, salt)
    aesgcm = AESGCM(key)

    chunk_index = 0
    bytes_read = len(MAGIC_HEADER) + SALT_SIZE

    while True:
        nonce = in_file.read(NONCE_SIZE)
        if not nonce:
            # EOF reached
            if chunk_index == 0:
                raise ValueError("Encrypted file contains no payload chunks.")
            raise ValueError("Unexpected EOF: File was truncated before final chunk.")
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"Truncated chunk header at index {chunk_index}.")

        len_bytes = in_file.read(4)
        if len(len_bytes) != 4:
            raise ValueError(f"Truncated chunk size header at index {chunk_index}.")

        chunk_len = struct.unpack(">I", len_bytes)[0]
        ciphertext = in_file.read(chunk_len)
        if len(ciphertext) != chunk_len:
            raise ValueError(f"Truncated chunk payload at index {chunk_index}.")

        # Decode nonce info
        is_final = nonce[11]
        decoded_idx = int.from_bytes(nonce[4:11], byteorder='big')

        if decoded_idx != chunk_index:
            raise ValueError(f"Tamper detected: Chunk reordered or index mismatch (expected {chunk_index}, got {decoded_idx}).")

        aad = struct.pack(">QB", chunk_index, is_final)

        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception:
            raise ValueError(f"Decryption failed at chunk {chunk_index}: Wrong password/keyfile or file corrupted/tampered.")

        out_stream.write(plaintext)

        bytes_read += NONCE_SIZE + 4 + chunk_len
        chunk_index += 1

        if progress_callback and total_size and total_size > 0:
            progress_callback(min(bytes_read / total_size, 1.0))

        if is_final:
            # Ensure no trailing extra bytes exist after final chunk
            extra = in_file.read(1)
            if extra:
                raise ValueError("Tamper detected: Extra bytes found after final chunk.")
            break

def is_safe_tar_member(member, target_dir):
    """
    Guards against Zip/Tar Slip vulnerabilities by checking target path.
    """
    target_dir = os.path.abspath(target_dir)
    member_path = os.path.abspath(os.path.join(target_dir, member.name))
    return os.path.commonpath([target_dir, member_path]) == target_dir

def encrypt_path(source_path: str, output_path: str, password: str, keyfile_path: str = None, wipe_original: bool = False, progress_callback=None):
    """
    Encrypts a file or directory safely to output_path.
    """
    keyfile_bytes = None
    if keyfile_path:
        with open(keyfile_path, "rb") as kf:
            keyfile_bytes = kf.read()

    is_dir = os.path.isdir(source_path)
    temp_tar_file = None

    try:
        if is_dir:
            # Create temp tar file for directory
            temp_tar = tempfile.NamedTemporaryFile(delete=False, suffix=".tar")
            temp_tar_path = temp_tar.name
            temp_tar.close()

            with tarfile.open(temp_tar_path, "w") as tar:
                tar.add(source_path, arcname=os.path.basename(source_path))

            total_size = os.path.getsize(temp_tar_path)
            in_stream = open(temp_tar_path, "rb")
        else:
            total_size = os.path.getsize(source_path)
            in_stream = open(source_path, "rb")

        # Write to temporary output file for safe atomic output
        temp_out = tempfile.NamedTemporaryFile(delete=False, dir=os.path.dirname(os.path.abspath(output_path)) or ".")
        temp_out_path = temp_out.name

        try:
            encrypt_stream(in_stream, temp_out, password, keyfile_bytes, progress_callback, total_size)
            in_stream.close()
            temp_out.close()

            if is_dir:
                os.remove(temp_tar_path)

            if os.path.exists(output_path):
                os.remove(output_path)
            os.rename(temp_out_path, output_path)

            if wipe_original:
                if is_dir:
                    for root, dirs, files in os.walk(source_path, topdown=False):
                        for file in files:
                            wipe_file(os.path.join(root, file))
                        for d in dirs:
                            os.rmdir(os.path.join(root, d))
                    os.rmdir(source_path)
                else:
                    wipe_file(source_path)

        except Exception as e:
            temp_out.close()
            if os.path.exists(temp_out_path):
                os.remove(temp_out_path)
            raise e
        finally:
            if in_stream and not in_stream.closed:
                in_stream.close()

    except Exception as e:
        if is_dir and 'temp_tar_path' in locals() and os.path.exists(temp_tar_path):
            os.remove(temp_tar_path)
        raise e

def decrypt_path(aev_path: str, output_path: str, password: str, keyfile_path: str = None, progress_callback=None):
    """
    Decrypts an .aev file to output_path. Decrypts to a temp file first (safe failure).
    If decrypted output is a tar archive, extracts it to output directory.
    """
    keyfile_bytes = None
    if keyfile_path:
        with open(keyfile_path, "rb") as kf:
            keyfile_bytes = kf.read()

    total_size = os.path.getsize(aev_path)
    out_dir = os.path.dirname(os.path.abspath(output_path)) or "."

    temp_out = tempfile.NamedTemporaryFile(delete=False, dir=out_dir)
    temp_out_path = temp_out.name

    try:
        with open(aev_path, "rb") as in_file:
            decrypt_stream(in_file, temp_out, password, keyfile_bytes, progress_callback, total_size)
        temp_out.close()

        # Check if the decrypted file is a TAR archive
        is_tar = False
        try:
            if tarfile.is_tarfile(temp_out_path):
                is_tar = True
        except Exception:
            is_tar = False

        if is_tar:
            # Extract tar archive safely
            dest_dir = output_path
            if not os.path.exists(dest_dir):
                os.makedirs(dest_dir, exist_ok=True)

            with tarfile.open(temp_out_path, "r") as tar:
                for member in tar.getmembers():
                    if not is_safe_tar_member(member, dest_dir):
                        raise ValueError(f"Security Alert: Blocked path traversal attempt in archive member '{member.name}'.")
                if hasattr(tarfile, 'data_filter'):
                    tar.extractall(path=dest_dir, filter='data')
                else:
                    tar.extractall(path=dest_dir)

            os.remove(temp_out_path)
        else:
            if os.path.exists(output_path) and os.path.isdir(output_path):
                # If output path is directory, save with original filename without .aev
                base_name = os.path.basename(aev_path)
                if base_name.endswith('.aev'):
                    base_name = base_name[:-4]
                output_path = os.path.join(output_path, base_name)

            if os.path.exists(output_path):
                os.remove(output_path)
            os.rename(temp_out_path, output_path)

    except Exception as e:
        temp_out.close()
        if os.path.exists(temp_out_path):
            os.remove(temp_out_path)
        raise e

def calculate_password_strength(password: str):
    """
    Returns entropy bit score and rating label for a password.
    """
    if not password:
        return 0, "Empty", "#888888"

    pool_size = 0
    if any(c in string.ascii_lowercase for c in password):
        pool_size += 26
    if any(c in string.ascii_uppercase for c in password):
        pool_size += 26
    if any(c in string.digits for c in password):
        pool_size += 10
    if any(c in string.punctuation for c in password):
        pool_size += 32

    if pool_size == 0:
        pool_size = 128

    entropy = len(password) * math.log2(pool_size)

    if entropy < 36:
        return entropy, "Very Weak", "#d9534f"
    elif entropy < 56:
        return entropy, "Weak", "#f0ad4e"
    elif entropy < 80:
        return entropy, "Moderate", "#5bc0de"
    elif entropy < 100:
        return entropy, "Strong", "#5cb85c"
    else:
        return entropy, "Very Strong (Overkill)", "#0275d8"

def generate_secure_password(length=24):
    """
    Generates a cryptographically strong random password.
    """
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(chars) for _ in range(length))

def register_win_file_association():
    """
    Registers .aev file extension in Windows Registry so double-clicking .aev files opens AegisVault.
    """
    if sys.platform != "win32":
        return False, "File association is only supported on Windows OS."
    try:
        import winreg
        python_exe = sys.executable
        script_path = os.path.abspath(__file__)
        pythonw_exe = python_exe.replace("python.exe", "pythonw.exe")
        if not os.path.exists(pythonw_exe):
            pythonw_exe = python_exe

        command = f'"{pythonw_exe}" "{script_path}" "%1"'

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\.aev") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, "AegisVault.EncryptedFile")

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\AegisVault.EncryptedFile") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, "AegisVault Encrypted File")

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\AegisVault.EncryptedFile\shell\open\command") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, command)

        return True, "Successfully associated .aev files with AegisVault!\nDouble-clicking any .aev file will now automatically open AegisVault."
    except Exception as e:
        return False, f"Failed to register file association: {str(e)}"

# GUI Class using Tkinter
class AegisVaultGUI:
    def __init__(self, root, initial_file=None):
        self.root = root
        self.root.title("AegisVault - Advanced AES-256-GCM Encryption Tool")
        self.root.geometry("640x660")
        self.root.minsize(600, 620)
        self.root.resizable(True, True)

        # Style configurations
        style = ttk.Style()
        style.theme_use('clam')

        # Variables
        self.mode_var = tk.StringVar(value="encrypt")
        self.input_path_var = tk.StringVar()
        self.output_path_var = tk.StringVar()
        self.keyfile_path_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.show_pass_var = tk.BooleanVar(value=False)
        self.wipe_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Ready")

        self.password_var.trace_add("write", self._on_password_change)

        self._build_ui()

        if initial_file:
            self._load_initial_file(initial_file)

    def _load_initial_file(self, path):
        abs_path = os.path.abspath(path)
        self.input_path_var.set(abs_path)
        if abs_path.lower().endswith('.aev'):
            self.mode_var.set("decrypt")
            self._on_mode_change()
            out_path = abs_path[:-4] if abs_path.endswith('.aev') else abs_path + ".dec"
            if out_path.endswith('.tar'):
                out_path = out_path[:-4] + "_extracted"
            self.output_path_var.set(out_path)
        else:
            self.mode_var.set("encrypt")
            self._on_mode_change()
            self.output_path_var.set(abs_path + (".tar.aev" if os.path.isdir(abs_path) else ".aev"))
        
        self.pass_entry.focus_set()

    def _build_ui(self):
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title / Banner
        title_label = ttk.Label(main_frame, text="🛡️ AegisVault Encryption Tool", font=("Segoe UI", 16, "bold"))
        title_label.pack(anchor="w", pady=(0, 2))
        subtitle = ttk.Label(main_frame, text="Streaming AES-256-GCM with Scrypt 2FA & Tamper Protection", font=("Segoe UI", 9, "italic"))
        subtitle.pack(anchor="w", pady=(0, 15))

        # Mode Selection
        mode_frame = ttk.LabelFrame(main_frame, text=" Operation Mode ", padding="10")
        mode_frame.pack(fill=tk.X, pady=5)
        ttk.Radiobutton(mode_frame, text="Encrypt (File or Directory)", variable=self.mode_var, value="encrypt", command=self._on_mode_change).pack(side=tk.LEFT, padx=15)
        ttk.Radiobutton(mode_frame, text="Decrypt (.aev Archive)", variable=self.mode_var, value="decrypt", command=self._on_mode_change).pack(side=tk.LEFT, padx=15)

        # File & Output Selection
        files_frame = ttk.LabelFrame(main_frame, text=" Input / Output Paths ", padding="10")
        files_frame.pack(fill=tk.X, pady=5)

        # Source Path
        ttk.Label(files_frame, text="Input File/Folder:").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(files_frame, textvariable=self.input_path_var, width=45).grid(row=0, column=1, padx=5, pady=4)
        btn_browse_in = ttk.Button(files_frame, text="Browse...", command=self._browse_input)
        btn_browse_in.grid(row=0, column=2, pady=4)

        # Destination Path
        ttk.Label(files_frame, text="Output Path:").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(files_frame, textvariable=self.output_path_var, width=45).grid(row=1, column=1, padx=5, pady=4)
        btn_browse_out = ttk.Button(files_frame, text="Browse...", command=self._browse_output)
        btn_browse_out.grid(row=1, column=2, pady=4)

        # Key & Password Options
        key_frame = ttk.LabelFrame(main_frame, text=" Security & Authentication ", padding="10")
        key_frame.pack(fill=tk.X, pady=5)

        ttk.Label(key_frame, text="Password:").grid(row=0, column=0, sticky="w", pady=4)
        self.pass_entry = ttk.Entry(key_frame, textvariable=self.password_var, show="*", width=32)
        self.pass_entry.grid(row=0, column=1, sticky="w", padx=5, pady=4)

        chk_show = ttk.Checkbutton(key_frame, text="Show", variable=self.show_pass_var, command=self._toggle_password)
        chk_show.grid(row=0, column=2, sticky="w")

        btn_gen = ttk.Button(key_frame, text="Generate Pass", command=self._generate_password)
        btn_gen.grid(row=0, column=3, padx=5)

        # Strength meter
        ttk.Label(key_frame, text="Strength:").grid(row=1, column=0, sticky="w", pady=2)
        self.lbl_strength = tk.Label(key_frame, text="Empty", font=("Segoe UI", 9, "bold"), fg="#888888")
        self.lbl_strength.grid(row=1, column=1, sticky="w", padx=5, pady=2)

        # Optional Keyfile
        ttk.Label(key_frame, text="Keyfile (2FA - Optional):").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(key_frame, textvariable=self.keyfile_path_var, width=32).grid(row=2, column=1, sticky="w", padx=5, pady=4)
        ttk.Button(key_frame, text="Select Keyfile", command=self._browse_keyfile).grid(row=2, column=2, columnspan=2, sticky="w")

        # Additional options
        opts_frame = ttk.Frame(main_frame)
        opts_frame.pack(fill=tk.X, pady=5)
        self.chk_wipe = ttk.Checkbutton(opts_frame, text="Best-effort wipe original after encryption", variable=self.wipe_var)
        self.chk_wipe.pack(side=tk.LEFT)
        btn_assoc = ttk.Button(opts_frame, text="Associate .aev in Windows", command=self._register_association)
        btn_assoc.pack(side=tk.RIGHT)

        # Style custom action button
        style = ttk.Style()
        style.configure("Accent.TButton", font=("Segoe UI", 11, "bold"))

        # Progress bar & Status
        prog_frame = ttk.Frame(main_frame)
        prog_frame.pack(fill=tk.X, pady=(5, 5))
        self.progress_bar = ttk.Progressbar(prog_frame, orient="horizontal", mode="determinate")
        self.progress_bar.pack(fill=tk.X, pady=(0, 2))
        self.lbl_status = ttk.Label(prog_frame, textvariable=self.status_var, font=("Segoe UI", 9))
        self.lbl_status.pack(anchor="w")

        # Execute Button
        self.btn_action = ttk.Button(main_frame, text="🔒 ENCRYPT NOW", style="Accent.TButton", command=self._start_process)
        self.btn_action.pack(fill=tk.X, pady=(8, 5), ipady=8)

    def _on_mode_change(self):
        if self.mode_var.get() == "encrypt":
            self.btn_action.config(text="🔒 ENCRYPT NOW")
            self.chk_wipe.config(state=tk.NORMAL)
        else:
            self.btn_action.config(text="🔓 DECRYPT NOW")
            self.chk_wipe.config(state=tk.DISABLED)

    def _on_password_change(self, *args):
        password = self.password_var.get()
        entropy, rating, color = calculate_password_strength(password)
        self.lbl_strength.config(text=f"{rating} ({int(entropy)} bits)", fg=color)

    def _toggle_password(self):
        if self.show_pass_var.get():
            self.pass_entry.config(show="")
        else:
            self.pass_entry.config(show="*")

    def _generate_password(self):
        pwd = generate_secure_password(24)
        self.password_var.set(pwd)
        self.show_pass_var.set(True)
        self.pass_entry.config(show="")
        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)
        messagebox.showinfo("Password Generated", "Generated a strong 24-character password and copied it to clipboard!")

    def _browse_input(self):
        if self.mode_var.get() == "encrypt":
            choice = messagebox.askyesnocancel("Select Input Type", "Click YES to choose a File, NO to choose a Directory/Folder")
            if choice is True:
                path = filedialog.askopenfilename(title="Select File to Encrypt")
                if path:
                    self.input_path_var.set(path)
                    if not self.output_path_var.get():
                        self.output_path_var.set(path + ".aev")
            elif choice is False:
                path = filedialog.askdirectory(title="Select Directory to Encrypt")
                if path:
                    self.input_path_var.set(path)
                    if not self.output_path_var.get():
                        self.output_path_var.set(path + ".tar.aev")
        else:
            path = filedialog.askopenfilename(title="Select .aev File to Decrypt", filetypes=[("AegisVault Files", "*.aev"), ("All Files", "*.*")])
            if path:
                self.input_path_var.set(path)
                if not self.output_path_var.get():
                    out_path = path[:-4] if path.endswith('.aev') else path + ".decrypted"
                    if out_path.endswith('.tar'):
                        out_path = out_path[:-4] + "_extracted"
                    self.output_path_var.set(out_path)

    def _browse_output(self):
        if self.mode_var.get() == "encrypt":
            path = filedialog.asksaveasfilename(title="Select Encrypted Output Location", filetypes=[("AegisVault Files", "*.aev"), ("All Files", "*.*")])
        else:
            path = filedialog.asksaveasfilename(title="Select Decrypted Output Location")
        if path:
            self.output_path_var.set(path)

    def _browse_keyfile(self):
        path = filedialog.askopenfilename(title="Select Keyfile for 2FA")
        if path:
            self.keyfile_path_var.set(path)

    def _register_association(self):
        success, msg = register_win_file_association()
        if success:
            messagebox.showinfo("File Association", msg)
        else:
            messagebox.showerror("File Association Error", msg)

    def _update_progress(self, ratio):
        self.progress_bar['value'] = ratio * 100
        self.root.update_idletasks()

    def _start_process(self):
        inp = self.input_path_var.get().strip()
        out = self.output_path_var.get().strip()
        pwd = self.password_var.get()
        keyf = self.keyfile_path_var.get().strip() or None

        if not inp or not os.path.exists(inp):
            messagebox.showerror("Error", "Please select a valid input file or directory.")
            return
        if not out:
            messagebox.showerror("Error", "Please specify an output path.")
            return
        if not pwd:
            messagebox.showerror("Error", "Password cannot be empty.")
            return

        mode = self.mode_var.get()
        self.btn_action.config(state=tk.DISABLED)
        self.progress_bar['value'] = 0

        def run_thread():
            try:
                if mode == "encrypt":
                    self.status_var.set("Deriving keys & encrypting...")
                    encrypt_path(inp, out, pwd, keyf, self.wipe_var.get(), self._update_progress)
                    self.status_var.set("Encryption completed successfully!")
                    messagebox.showinfo("Success", f"File successfully encrypted to:\n{out}")
                else:
                    self.status_var.set("Verifying & decrypting...")
                    decrypt_path(inp, out, pwd, keyf, self._update_progress)
                    self.status_var.set("Decryption completed successfully!")
                    ans = messagebox.askyesno("Decryption Successful", f"File successfully decrypted to:\n{out}\n\nWould you like to open the decrypted file/folder now?")
                    if ans:
                        try:
                            if sys.platform == "win32":
                                os.startfile(out)
                            elif sys.platform == "darwin":
                                import subprocess
                                subprocess.run(["open", out])
                            else:
                                import subprocess
                                subprocess.run(["xdg-open", out])
                        except Exception as open_err:
                            messagebox.showwarning("Open File Warning", f"Decrypted successfully, but could not auto-open: {open_err}")
            except Exception as e:
                self.status_var.set(f"Operation failed: {str(e)}")
                messagebox.showerror("Error", f"Operation failed:\n{str(e)}")
            finally:
                self.btn_action.config(state=tk.NORMAL)

        threading.Thread(target=run_thread, daemon=True).start()


# CLI Entry point
def main():
    if len(sys.argv) == 1:
        # Launch Tkinter GUI
        root = tk.Tk()
        app = AegisVaultGUI(root)
        root.mainloop()
        return

    # Check if single argument is passed (e.g. file double clicked or opened via python aegisvault.py filename)
    if len(sys.argv) == 2:
        arg = sys.argv[1]
        if arg == "register":
            success, msg = register_win_file_association()
            print(msg)
            return
        elif not arg.startswith("-") and arg not in ("enc", "dec"):
            root = tk.Tk()
            app = AegisVaultGUI(root, initial_file=arg)
            root.mainloop()
            return
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Encrypt subparser
    enc_parser = subparsers.add_parser("enc", help="Encrypt file or directory")
    enc_parser.add_argument("source", help="Source file or directory path")
    enc_parser.add_argument("-o", "--output", help="Output .aev file path")
    enc_parser.add_argument("-p", "--password", help="Encryption password")
    enc_parser.add_argument("-k", "--keyfile", help="Path to 2FA keyfile")
    enc_parser.add_argument("--wipe", action="store_true", help="Best-effort wipe of original source after encryption")

    # Decrypt subparser
    dec_parser = subparsers.add_parser("dec", help="Decrypt .aev file")
    dec_parser.add_argument("source", help="Encrypted .aev file path")
    dec_parser.add_argument("-o", "--output", help="Output decrypted file/directory path")
    dec_parser.add_argument("-p", "--password", help="Decryption password")
    dec_parser.add_argument("-k", "--keyfile", help="Path to 2FA keyfile")

    args = parser.parse_args()

    password = args.password
    if not password:
        import getpass
        password = getpass.getpass("Enter password: ")

    source_path = args.source
    if not os.path.exists(source_path):
        print(f"Error: Source path '{source_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    if args.command == "enc":
        output_path = args.output
        if not output_path:
            if os.path.isdir(source_path):
                output_path = source_path.rstrip("/\\") + ".tar.aev"
            else:
                output_path = source_path + ".aev"
        
        print(f"Encrypting '{source_path}' -> '{output_path}'...")
        def progress(r):
            print(f"\rProgress: {int(r * 100)}%", end="", flush=True)

        try:
            encrypt_path(source_path, output_path, password, args.keyfile, args.wipe, progress)
            print("\nEncryption complete!")
        except Exception as e:
            print(f"\nEncryption failed: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "dec":
        output_path = args.output
        if not output_path:
            output_path = source_path[:-4] if source_path.endswith('.aev') else source_path + ".dec"
            if output_path.endswith('.tar'):
                output_path = output_path[:-4] + "_extracted"

        print(f"Decrypting '{source_path}' -> '{output_path}'...")
        def progress(r):
            print(f"\rProgress: {int(r * 100)}%", end="", flush=True)

        try:
            decrypt_path(source_path, output_path, password, args.keyfile, progress)
            print("\nDecryption complete!")
        except Exception as e:
            print(f"\nDecryption failed: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
