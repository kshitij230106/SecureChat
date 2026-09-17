from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
import base64

KEY_FOLDER = "keys"


def create_key_folder():
    if not os.path.exists(KEY_FOLDER):
        os.makedirs(KEY_FOLDER)


def generate_keys(username):
    create_key_folder()

    private_path = os.path.join(KEY_FOLDER, username + "_private.pem")

    public_path = os.path.join(KEY_FOLDER, username + "_public.pem")

    # Don't generate new keys if they already exist
    if os.path.exists(private_path) and os.path.exists(public_path):
        return private_path, public_path

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    public_key = private_key.public_key()

    with open(private_path, "wb") as file:
        file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(public_path, "wb") as file:
        file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    return private_path, public_path


def load_private_key(username):
    private_path = os.path.join(KEY_FOLDER, username + "_private.pem")

    with open(private_path, "rb") as file:
        return serialization.load_pem_private_key(file.read(), password=None)


def load_public_key(username):
    public_path = os.path.join(KEY_FOLDER, username + "_public.pem")

    with open(public_path, "rb") as file:
        return serialization.load_pem_public_key(file.read())


def get_public_key_text(username):
    public_path = os.path.join(KEY_FOLDER, username + "_public.pem")

    with open(public_path, "rb") as file:
        return base64.b64encode(file.read()).decode()


def public_key_from_text(public_key_text):
    key_data = base64.b64decode(public_key_text.encode())

    return serialization.load_pem_public_key(key_data)


if __name__ == "__main__":

    username = "TestUser"

    private_path, public_path = generate_keys(username)

    print("Keys generated successfully.")

    print("Private key:", private_path)

    print("Public key:", public_path)
