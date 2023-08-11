# Cryptographic Encryption and Decryption

This Python script provides a simple comusing the AES-Gmand-line interface for encrypting and decrypting messages CM (Advanced Encryption Standard - Galois/Counter Mode) authenticated encryption scheme. The script uses the cryptography library for cryptographic operations and follows best practices for securely deriving encryption keys from user-provided passwords.

## Functions

### `generate_salt()`

Generates a random 16-byte salt, which is used to strengthen the key derivation process.

### `derive_key(password, salt)`

Derives a secure encryption key from a given password and salt using the PBKDF2-HMAC key derivation function with SHA-256 as the underlying hash function. The key length is set to 32 bytes (256 bits), suitable for AES-256 encryption.

### `encrypt(plaintext, password)`

Encrypts a given plaintext message using the AES-GCM authenticated encryption scheme. This function generates a new salt, derives an encryption key from the password and salt, and then uses AES-GCM to encrypt the message.

### `decrypt(salt, ciphertext_b64, password)`

Decrypts a given ciphertext message using the previously used salt and the provided password. This function uses AES-GCM for authenticated decryption.

### `main()`

The main entry point of the script. It prompts the user to choose between encryption and decryption. Based on the choice, the user is prompted to provide a message and a password. The script handles the encryption or decryption process based on the user's input.

## Usage

1. Run the script, and it will repeatedly ask whether to encrypt or decrypt a message.
2. If "encrypt" is chosen, the user is prompted to enter a message and a password. The script will encrypt the message and display the salt used and the base64-encoded ciphertext.
3. If "decrypt" is chosen, the user needs to provide the salt and the base64-encoded ciphertext along with the password. The script will attempt to decrypt the ciphertext and display the original message.

## Note

This script serves as a demonstration of cryptographic concepts and is not intended for production use. In a real-world scenario, additional security measures, key management, and error handling should be implemented. Additionally, it's essential to keep the cryptography library up to date with the latest security patches.

Please exercise caution when handling sensitive information, and ensure you understand the security implications of any cryptographic system you use.
