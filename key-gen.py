from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keys():
    """
    Generates RSA public and private keys for both sender and receiver.
    
    Returns:
    - sender_private_key: Private key of the sender.
    - sender_public_key: Public key of the sender.
    - receiver_private_key: Private key of the receiver.
    - receiver_public_key: Public key of the receiver.
    """
    # Generate sender's keys
    sender_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    sender_public_key = sender_private_key.public_key()

    # Generate receiver's keys
    receiver_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    receiver_public_key = receiver_private_key.public_key()

    return sender_private_key, sender_public_key, receiver_private_key, receiver_public_key

def save_keys(private_key, public_key, private_key_filename, public_key_filename):
    """
    Saves private and public keys to files.
    
    Args:
    - private_key: Private key to be saved.
    - public_key: Public key to be saved.
    - private_key_filename: Filename to save the private key.
    - public_key_filename: Filename to save the public key.
    """
    # Save sender's private key
    with open(private_key_filename, "wb") as private_key_file:
        private_key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save sender's public key
    with open(public_key_filename, "wb") as public_key_file:
        public_key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

if __name__ == "__main__":
    # Generate keys for sender and receiver
    sender_private_key, sender_public_key, receiver_private_key, receiver_public_key = generate_keys()
    
    # Save keys to files
    save_keys(sender_private_key, sender_public_key, "sender_private_key.pem", "sender_public_key.pem")
    save_keys(receiver_private_key, receiver_public_key, "receiver_private_key.pem", "receiver_public_key.pem")
    
    print("Keys generated and saved successfully.")
