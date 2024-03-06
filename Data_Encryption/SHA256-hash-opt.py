import hashlib

def generate_sha256_hash(data):
    """
    Generates SHA256 hash for the given data.
    
    Args:
    - data: The input data to be hashed.
    
    Returns:
    - The SHA256 hash of the input data.
    """
    sha256_hash = hashlib.sha256(data).hexdigest()
    return sha256_hash

def hash_text():
    """
    Allows the user to input text and generates SHA256 hash for it.
    """
    text = input("Enter text to hash: ")
    sha256_hash = generate_sha256_hash(text.encode())
    print("SHA256 Hash:", sha256_hash)

def hash_file(file_path):
    """
    Generates SHA256 hash for the content of the specified file.
    
    Args:
    - file_path: The path of the file to be hashed.
    """
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
            sha256_hash = generate_sha256_hash(file_data)
            print("SHA256 Hash:", sha256_hash)
    except FileNotFoundError:
        print("File not found.")

if __name__ == "__main__":
    print("Options:")
    print("1. Input Text")
    print("2. Upload File")
    choice = input("Enter your choice (1 or 2): ")

    if choice == '1':
        hash_text()
    elif choice == '2':
        file_path = input("Enter the path of the file: ")
        hash_file(file_path)
    else:
        print("Invalid choice.")