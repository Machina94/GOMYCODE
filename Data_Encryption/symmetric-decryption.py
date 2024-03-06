from cryptography.fernet import Fernet

def load_symmetric_key(key_file):
    """
    Load the symmetric encryption key from a file.

    Args:
    - key_file: Path to the file containing the symmetric key.

    Returns:
    - symmetric_key: The loaded symmetric encryption key.
    """
    with open(key_file, "rb") as file:
        symmetric_key = file.read()

    return symmetric_key

def decrypt_file(ciphertext_file_path, symmetric_key):
    """
    Decrypt a ciphertext file using a symmetric key.

    Args:
    - ciphertext_file_path: Path to the ciphertext file to be decrypted.
    - symmetric_key: Symmetric key used for decryption.
    """
    with open(ciphertext_file_path, "rb") as file:
        ciphertext_data = file.read()

    fernet = Fernet(symmetric_key)
    decrypted_data = fernet.decrypt(ciphertext_data)

    return decrypted_data

if __name__ == "__main__":
    # Input the path to the file containing the symmetric key
    key_file_path = input("Enter the path to the file containing the symmetric key: ")

    # Load the symmetric key
    symmetric_key = load_symmetric_key(key_file_path)

    # Input the path of the ciphertext file to decrypt
    ciphertext_file_path = input("Enter the path of the ciphertext file to decrypt: ")

    # Decrypt the file
    decrypted_data = decrypt_file(ciphertext_file_path, symmetric_key)

    # Write the decrypted data to a new file
    decrypted_file_name = input("Enter the name of the decrypted file (with extension): ")
    with open(decrypted_file_name, "wb") as file:
        file.write(decrypted_data)

    print("File decrypted successfully.")
