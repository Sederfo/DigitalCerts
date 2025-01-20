from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import os
import time

def derive_keys(master_key: bytes, salt: bytes, num_keys: int, key_size: int = 8) -> list:
    derived_key_material = PBKDF2(master_key, salt, dkLen=num_keys * key_size, count=100000, hmac_hash_module=SHA256)
    return [derived_key_material[i * key_size:(i + 1) * key_size] for i in range(num_keys)]

def xor_bytes(data: bytes, key: bytes) -> bytes:
    key_length = len(key)
    return bytes(data[i] ^ key[i % key_length] for i in range(len(data)))

def des_encrypt_with_iv(key: bytes, data: bytes, iv: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.encrypt(data)

def des_decrypt_with_iv(key: bytes, data: bytes, iv: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.decrypt(data)

def custom_desx3_encrypt_with_iv(plaintext: bytes, k1: bytes, k2: bytes, k3: bytes, k4: bytes) -> bytes:
    iv = get_random_bytes(8)
    padded_plaintext = pad(plaintext, DES.block_size)
    pre_whitened = xor_bytes(padded_plaintext, k1)
    stage1 = des_encrypt_with_iv(k2, pre_whitened, iv)
    stage2 = des_decrypt_with_iv(k3, stage1, iv)
    post_whitened = xor_bytes(stage2, k1)
    stage3 = des_encrypt_with_iv(k4, post_whitened, iv)
    return iv + stage3

def custom_desx3_decrypt_with_iv(ciphertext: bytes, k1: bytes, k2: bytes, k3: bytes, k4: bytes) -> bytes:
    iv = ciphertext[:8]
    ciphertext = ciphertext[8:]
    stage1 = des_decrypt_with_iv(k4, ciphertext, iv)
    post_whitened = xor_bytes(stage1, k1)
    stage2 = des_encrypt_with_iv(k3, post_whitened, iv)
    stage3 = des_decrypt_with_iv(k2, stage2, iv)
    pre_whitened = xor_bytes(stage3, k1)
    plaintext = unpad(pre_whitened, DES.block_size)
    return plaintext

def brute_force_key4(ciphertext, k1, k2, k3, plaintext, key_space_size=256):
    print("Starting brute force on K4...")
    iv = ciphertext[:8]
    start_time = time.time()

    for key_guess in (bytes([a] * 8) for a in range(key_space_size)):
        try:
            decrypted = custom_desx3_decrypt_with_iv(ciphertext, k1, k2, k3, key_guess)
            if decrypted == plaintext:
                elapsed_time = time.time() - start_time
                print(f"Key found: {key_guess}")
                print(f"Time taken: {elapsed_time} seconds")
                return key_guess
        except Exception:
            continue

    elapsed_time = time.time() - start_time
    print(f"Key not found in given key space after {elapsed_time} seconds.")
    return None

if __name__ == "__main__":
    # Example Usage
    master_key = os.urandom(32)
    salt = get_random_bytes(16)
    k1, k2, k3, k4 = derive_keys(master_key, salt, num_keys=4)

    plaintext = b"This is a test message"
    print(f"Original plaintext: {plaintext}")

    ciphertext = custom_desx3_encrypt_with_iv(plaintext, k1, k2, k3, k4)
    print(f"Ciphertext: {ciphertext.hex()}")

    decrypted = custom_desx3_decrypt_with_iv(ciphertext, k1, k2, k3, k4)
    print(f"Decrypted plaintext: {decrypted}")

    # Brute force K4
    brute_forced_k4 = brute_force_key4(ciphertext, k1, k2, k3, plaintext)
    print(f"Brute-forced K4: {brute_forced_k4}")
