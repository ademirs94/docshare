from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def encrypt_file(data):
    key = os.urandom(32)  # AES-256
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return key, iv + ciphertext  # guarda o IV no início do ficheiro

def encrypt_key(key, master_key):
    iv = os.urandom(16)
    print(len(master_key))
    cipher = Cipher(algorithms.AES(master_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(key) + encryptor.finalize()
    return iv + encrypted_key

def decrypt_file(encrypted_data, key):
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data[16:]) + decryptor.finalize()

def decrypt_key(encrypted_key, master_key):
    iv = encrypted_key[:16]
    cipher = Cipher(algorithms.AES(master_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_key[16:]) + decryptor.finalize()
