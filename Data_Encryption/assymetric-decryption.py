from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def load_private_key(key_file):
    """
    Load the private key from a file.

    Args:
    - key_file: Path to the private key file.

    Returns:
    - private_key: The loaded private key object.
    """
    with open(key_file, "rb") as file:
        private_key = serialization.load_pem_private_key(
            file.read(),
            password=None
        )
    return private_key

def decrypt_data(encrypted_data, private_key):
    """
    Decrypt the encrypted data using the private key.

    Args:
    - encrypted_data: The data to decrypt.
    - private_key: The private key used for decryption.

    Returns:
    - decrypted_data: The decrypted data.
    """
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data

if __name__ == "__main__":
    # Load receiver's private key
    receiver_private_key_file = input("Enter the path of the receiver's private key file: ")
    receiver_private_key = load_private_key(receiver_private_key_file)

    # Input the path of the encrypted file
    encrypted_file_name = input("Enter the path of the encrypted file: ")
    with open(encrypted_file_name, "rb") as file:
        encrypted_data = file.read()

    # Decrypt the data
    decrypted_data = decrypt_data(encrypted_data, receiver_private_key)

    # Input the path to save the decrypted file
    decrypted_file_name = input("Enter the path to save the decrypted file: ")
    with open(decrypted_file_name, "wb") as file:
        file.write(decrypted_data)

    print("File decrypted successfully.")