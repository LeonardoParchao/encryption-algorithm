import os
import base64
import binascii
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac, padding, serialization, asymmetric, constant_time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_salt():
    return os.urandom(16)

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,  # Specify the length of the derived key (32 bytes for AES-256)
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def encrypt(plaintext, password):
    salt = generate_salt()
    key = derive_key(password.encode(), salt)
    
    # Use AES-GCM for authenticated encryption
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(salt, plaintext, None)
    
    ciphertext_b64 = base64.urlsafe_b64encode(ciphertext).decode('utf-8')
    return salt, ciphertext_b64

def decrypt(salt, ciphertext_b64, password):
    key = derive_key(password.encode(), salt)
    
    # Use AES-GCM for authenticated decryption
    aesgcm = AESGCM(key)
    ciphertext = base64.urlsafe_b64decode(ciphertext_b64.encode('utf-8'))
    plaintext = aesgcm.decrypt(salt, ciphertext, None)
    
    return plaintext

def main():
    while True:
        choice = input("Encrypt or decrypt: ").lower()
        if choice == "encrypt" or choice == "decrypt":
            message = input("Enter a message: ")
            password = input("Enter a password: ")
            
            if choice == "encrypt":
                try:
                    salt, ciphertext_b64 = encrypt(message.encode('utf-8'), password)
                    print("Encryption successful.")
                    print(f"Salt: {base64.urlsafe_b64encode(salt).decode('utf-8')}")
                    print(f"Encrypted message: {ciphertext_b64}")
                except Exception as e:
                    print("Encryption failed.")
                    print(e)
            else:
                try:
                    salt = base64.urlsafe_b64decode(input("Enter the salt: "))
                    ciphertext_b64 = input("Enter the encrypted message: ")
                    plaintext = decrypt(salt, ciphertext_b64, password)
                    print("Decryption successful.")
                    print(f"Decrypted message: {plaintext.decode('utf-8')}")
                except (ValueError, binascii.Error, Exception) as e:
                    print("Decryption failed.")
                    print(e)
        else:
            print("Invalid choice. Please enter 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()
