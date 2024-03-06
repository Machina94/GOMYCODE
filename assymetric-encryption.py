from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_file(file_path, public_key):
    with open(file_path, "rb") as file:
        file_data = file.read()
    encrypted_data = public_key.encrypt(
        file_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

def save_key(key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(key)

if __name__ == "__main__":
    # Generate sender's keys
    sender_private_key, sender_public_key = generate_keys()
    save_key(
        sender_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ), "sender_private_key.pem"
    )
    save_key(
        sender_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ), "sender_public_key.pem"
    )

    # Request receiver's public key
    receiver_public_key_file = input("Enter the path of the receiver's public key file: ")
    with open(receiver_public_key_file, "rb") as file:
        receiver_public_key = serialization.load_pem_public_key(
            file.read(),
            backend=None
        )

    # Encrypt file
    file_to_encrypt = input("Enter the path of the file to encrypt: ")
    encrypted_data = encrypt_file(file_to_encrypt, receiver_public_key)

    # Save encrypted file
    encrypted_file_name = os.path.splitext(file_to_encrypt)[0] + "_encrypted.bin"
    with open(encrypted_file_name, "wb") as file:
        file.write(encrypted_data)

    print("File encrypted successfully.")
