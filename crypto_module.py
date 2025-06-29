from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12) 
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(key)
    try:
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_data
    except Exception as e:
        print(f"Error decrypting data: {e}")
        return None