import hashlib

# Function to generate SHA256 hash
def generate_sha256_hash(data):
    sha256_hash = hashlib.sha256(data.encode()).hexdigest()
    return sha256_hash

# Example usage
if __name__ == "__main__":
    data = input("Enter data to hash: ")
    sha256_hash = generate_sha256_hash(data)
    print("SHA256 Hash:", sha256_hash)