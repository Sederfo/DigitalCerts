from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import os
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.x509 import load_pem_x509_certificate
import time
from desx3 import custom_desx3_encrypt_with_iv, custom_desx3_decrypt_with_iv
import pathlib
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

PATH = pathlib.Path(__file__).parent.absolute()

def derive_keys(master_key: bytes, salt: bytes, num_keys: int, key_size: int = 8) -> list:
    derived_key_material = PBKDF2(master_key, salt, dkLen=num_keys * key_size, count=100000, hmac_hash_module=SHA256)
    return [derived_key_material[i * key_size:(i + 1) * key_size] for i in range(num_keys)]


# Load certificates and keys
def load_key(file_path, private=True):
    with open(file_path, 'rb') as key_file:
        if private:
            return load_pem_private_key(key_file.read(), password=None)
        else:
            # Load the certificate and extract the public key
            cert = load_pem_x509_certificate(key_file.read())
            return cert.public_key()

# Generate and encrypt a symmetric key
def exchange_key(sender_private_key, receiver_public_key):
    # Generate a random symmetric master key
    symmetric_master_key = os.urandom(32)  # 256-bit key
    salt = get_random_bytes(16)

    # Generate keys needed for custom desx3 functions
    k1, k2, k3, k4 = derive_keys(symmetric_master_key, salt, num_keys=4)
    print(f"Generated Symmetric Master Key: {symmetric_master_key.hex()}")

    # Encrypt the symmetric key using the receiver's public key
    encrypted_key = receiver_public_key.encrypt(
        symmetric_master_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Encrypted Symmetric Master Key: {encrypted_key.hex()}")
    return (k1, k2, k3, k4), salt, encrypted_key

# Decrypt the symmetric key
def decrypt_key(receiver_private_key, encrypted_key, salt):
    # Decrypt the symmetric key using the receiver's private key
    symmetric_master_key = receiver_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    k1, k2, k3, k4 = derive_keys(symmetric_master_key, salt, num_keys=4)
    print(f"Decrypted Symmetric Master Key: {symmetric_master_key.hex()}")
    return k1, k2, k3, k4

# Symmetric encryption/decryption using the custom DES functions
def symmetric_encrypt(keys, plaintext):
    k1, k2, k3, k4 = keys
    ciphertext = custom_desx3_encrypt_with_iv(plaintext, k1, k2, k3, k4)
    return ciphertext

def symmetric_decrypt(keys, ciphertext):
    k1, k2, k3, k4 = keys
    plaintext = custom_desx3_decrypt_with_iv(ciphertext, k1, k2, k3, k4)
    return plaintext

# Example usage
if __name__ == "__main__":
    # Paths to your generated certificates and keys
    sender_private_key_path = PATH / "certs" / "sender_key.pem"
    receiver_public_key_path = PATH / "certs" / "receiver_cert.pem"
    receiver_private_key_path = PATH / "certs" / "receiver_key.pem"

    # Load keys
    sender_private_key = load_key(sender_private_key_path)
    receiver_public_key = load_key(receiver_public_key_path, private=False)
    receiver_private_key = load_key(receiver_private_key_path)

    # Exchange and encrypt a key
    symmetric_keys, salt, encrypted_key = exchange_key(sender_private_key, receiver_public_key)

    # Decrypt the key
    decrypted_keys = decrypt_key(receiver_private_key, encrypted_key, salt)

    # Encrypt and decrypt a message
    message = b"cryptography project"
    encrypted_message = symmetric_encrypt(decrypted_keys, message)
    decrypted_message = symmetric_decrypt(decrypted_keys, encrypted_message)

    print(f"Original Message: {message}")
    print(f"Encrypted Message: {encrypted_message.hex()}")
    print(f"Decrypted Message: {decrypted_message}")
