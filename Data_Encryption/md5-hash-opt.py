import hashlib

def generate_md5_hash(data):
    """
    Generates md5 hash for the given data.
    
    Args:
    - data: The input data to be hashed.
    
    Returns:
    - The md5 hash of the input data.
    """
    md5_hash = hashlib.md5(data).hexdigest()
    return md5_hash

def hash_text():
    """
    Allows the user to input text and generates md5 hash for it.
    """
    text = input("Enter text to hash: ")
    md5_hash = generate_md5_hash((text).encode())
    print("md5 Hash:", md5_hash)

def hash_file():
    """
    Allows the user to hash an already saved document using MD5.
    """
    file_path = input("Enter the path of the file: ")
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
            md5_hash = generate_md5_hash(file_data)
            print("md5 Hash:", md5_hash)
    except FileNotFoundError:
        print("File not found.")

if __name__ == "__main__":
    print("Options:")
    print("1. Hash Text")
    print("2. Hash File")
    choice = input("Enter your choice (1 or 2): ")

    if choice == '1':
        hash_text()
    elif choice == '2':
        hash_file()
    else:
        print("Invalid choice.")