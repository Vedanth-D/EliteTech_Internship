import os
import shutil
import hashlib
import tempfile
import unittest
from aegisvault import encrypt_path, decrypt_path

def get_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

class TestAegisVault(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="aegis_test_")
        self.password = "SuperSecretP@ssw0rd!2026"
        self.keyfile = os.path.join(self.test_dir, "usb_token.key")
        with open(self.keyfile, "wb") as f:
            f.write(os.urandom(32))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_pdf_encryption_decryption(self):
        """Test encryption and decryption of a PDF file."""
        pdf_path = os.path.join(self.test_dir, "sample.pdf")
        # Generate dummy PDF binary content
        with open(pdf_path, "wb") as f:
            f.write(b"%PDF-1.4\n" + os.urandom(500000) + b"\n%%EOF")

        enc_path = pdf_path + ".aev"
        dec_path = os.path.join(self.test_dir, "restored_sample.pdf")

        original_hash = get_sha256(pdf_path)

        # Encrypt with 2FA (password + keyfile)
        encrypt_path(pdf_path, enc_path, self.password, self.keyfile)
        self.assertTrue(os.path.exists(enc_path))

        # Decrypt
        decrypt_path(enc_path, dec_path, self.password, self.keyfile)
        self.assertTrue(os.path.exists(dec_path))

        restored_hash = get_sha256(dec_path)
        self.assertEqual(original_hash, restored_hash, "PDF SHA-256 mismatch after decryption!")
        print("[PASS] PDF encryption/decryption SHA-256 match test.")

    def test_large_file_streaming(self):
        """Test streaming encryption/decryption with a large file (> 3MB, multiple 1MB chunks)."""
        large_path = os.path.join(self.test_dir, "large_video.mp4")
        # 5 MB file to ensure multi-chunk processing
        with open(large_path, "wb") as f:
            f.write(os.urandom(5 * 1024 * 1024))

        enc_path = large_path + ".aev"
        dec_path = os.path.join(self.test_dir, "restored_video.mp4")

        original_hash = get_sha256(large_path)

        encrypt_path(large_path, enc_path, self.password, self.keyfile)
        decrypt_path(enc_path, dec_path, self.password, self.keyfile)

        restored_hash = get_sha256(dec_path)
        self.assertEqual(original_hash, restored_hash, "Large video SHA-256 mismatch after streaming decryption!")
        print("[PASS] Large file multi-chunk streaming SHA-256 match test.")

    def test_folder_encryption_decryption(self):
        """Test packing a whole directory as .tar.aev and restoring it."""
        folder_path = os.path.join(self.test_dir, "my_data_folder")
        os.makedirs(os.path.join(folder_path, "subfolder"), exist_ok=True)
        
        file1 = os.path.join(folder_path, "file1.txt")
        file2 = os.path.join(folder_path, "subfolder", "file2.bin")

        with open(file1, "w") as f:
            f.write("Hello AegisVault directory test!")
        with open(file2, "wb") as f:
            f.write(os.urandom(100000))

        hash1 = get_sha256(file1)
        hash2 = get_sha256(file2)

        enc_path = folder_path + ".tar.aev"
        extract_dir = os.path.join(self.test_dir, "extracted_folder")

        encrypt_path(folder_path, enc_path, self.password, self.keyfile)
        decrypt_path(enc_path, extract_dir, self.password, self.keyfile)

        restored_file1 = os.path.join(extract_dir, "my_data_folder", "file1.txt")
        restored_file2 = os.path.join(extract_dir, "my_data_folder", "subfolder", "file2.bin")

        self.assertTrue(os.path.exists(restored_file1))
        self.assertTrue(os.path.exists(restored_file2))
        self.assertEqual(hash1, get_sha256(restored_file1))
        self.assertEqual(hash2, get_sha256(restored_file2))
        print("[PASS] Directory packing & extraction SHA-256 match test.")

    def test_tamper_evidence_byte_flip(self):
        """Test that flipping a single byte in .aev causes decryption to refuse it."""
        file_path = os.path.join(self.test_dir, "confidential.doc")
        with open(file_path, "wb") as f:
            f.write(b"Top secret document content " * 1000)

        enc_path = file_path + ".aev"
        dec_path = os.path.join(self.test_dir, "restored.doc")

        encrypt_path(file_path, enc_path, self.password)

        # Corrupt one byte in the middle of ciphertext
        with open(enc_path, "rb") as f:
            data = bytearray(f.read())

        flip_idx = len(data) // 2
        data[flip_idx] ^= 0xFF  # Flip bits of one byte

        corrupted_enc_path = enc_path + ".bad"
        with open(corrupted_enc_path, "wb") as f:
            f.write(data)

        # Attempt decryption; expect ValueError
        with self.assertRaises(ValueError):
            decrypt_path(corrupted_enc_path, dec_path, self.password)

        self.assertFalse(os.path.exists(dec_path), "Temp output was not safely removed on failure!")
        print("[PASS] Tamper evidence (byte flip detection & safe cleanup) test.")

    def test_wrong_password_and_missing_keyfile(self):
        """Test that wrong password or missing keyfile fails safely without leaving corrupt files."""
        file_path = os.path.join(self.test_dir, "data.dat")
        with open(file_path, "wb") as f:
            f.write(os.urandom(50000))

        enc_path = file_path + ".aev"
        dec_path = os.path.join(self.test_dir, "restored.dat")

        # Encrypt with password + keyfile
        encrypt_path(file_path, enc_path, self.password, self.keyfile)

        # 1. Try wrong password with correct keyfile
        with self.assertRaises(ValueError):
            decrypt_path(enc_path, dec_path, "WrongPassword123", self.keyfile)
        self.assertFalse(os.path.exists(dec_path))

        # 2. Try correct password without keyfile
        with self.assertRaises(ValueError):
            decrypt_path(enc_path, dec_path, self.password, keyfile_path=None)
        self.assertFalse(os.path.exists(dec_path))

        # 3. Try correct password with invalid keyfile
        wrong_keyfile = os.path.join(self.test_dir, "wrong.key")
        with open(wrong_keyfile, "wb") as f:
            f.write(b"Different keyfile content")
        with self.assertRaises(ValueError):
            decrypt_path(enc_path, dec_path, self.password, wrong_keyfile)
        self.assertFalse(os.path.exists(dec_path))

        print("[PASS] Wrong password & missing keyfile test.")

if __name__ == "__main__":
    unittest.main()
