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

def encrypt_file(file_path, symmetric_key):
    """
    Encrypt a file using a symmetric key.

    Args:
    - file_path: Path to the file to be encrypted.
    - symmetric_key: Symmetric key used for encryption.
    """
    with open(file_path, "rb") as file:
        file_data = file.read()

    fernet = Fernet(symmetric_key)
    encrypted_data = fernet.encrypt(file_data)

    return encrypted_data

if __name__ == "__main__":
    # Input the path to the file containing the symmetric key
    key_file_path = input("Enter the path to the file containing the symmetric key: ")

    # Load the symmetric key
    symmetric_key = load_symmetric_key(key_file_path)

    # Input the path of the plain text file to encrypt
    plain_text_file_path = input("Enter the path of the plain text file to encrypt: ")

    # Encrypt the file
    encrypted_data = encrypt_file(plain_text_file_path, symmetric_key)

    # Write the encrypted data to a new file
    encrypted_file_name = input("Enter the name of the encrypted file (with extension): ")
    with open(encrypted_file_name, "wb") as file:
        file.write(encrypted_data)

    print("File encrypted successfully.")
