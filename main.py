import argparse
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as pad_asym
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives import hashes
import json
import os

with open('settings.json') as json_file:
    json_data = json.load(json_file)

path_initial_file = json_data["initial_file"]
path_encrypted_file = json_data["encrypted_file"]
path_decrypted_file = json_data["decrypted_file"]
path_symmetric_key = json_data["symmetric_key"]
path_public_key = json_data["public_key"]
path_secret_key = json_data["secret_key"]


def key_generation(path_to_symmetric_key: str, path_to_public_key: str, path_to_secret_key: str) -> None:
    symmetric_key = algorithms.IDEA(os.urandom(16))
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = rsa_key
    public_key = rsa_key.public_key()
    with open(path_to_public_key + os.sep + "public.pem", 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(path_to_secret_key + os.sep + "private.pem", 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))
    encrypt_symmetric_key = public_key.encrypt(symmetric_key.key,
                                               padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                            algorithm=hashes.SHA256(), label=None))
    with open(path_to_symmetric_key + os.sep + 'symmetric', 'wb') as symmetric_out:
        symmetric_out.write(encrypt_symmetric_key)


def encrypt_text(path_to_initial_file: str, path_to_secret_key: str, path_to_symmetric_key: str,
                 path_to_encrypt_file: str) -> None:
    with open(path_to_symmetric_key + os.sep + "symmetric.txt", mode='rb') as key_file:
        encrypt_symmetric_key = key_file.read()

    with open(path_to_secret_key + os.sep + "private.pem", 'rb') as pem_in:
        private_bytes = pem_in.read()
    d_private_key = load_pem_private_key(private_bytes, password=None)

    decrypt_symmetric_key = d_private_key.decrypt(encrypt_symmetric_key,
                                                  padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                               algorithm=hashes.SHA256(), label=None))

    with open(path_to_initial_file + os.sep + "initial_file.txt", 'r') as file:
        initial_file = file.read()

    padder = padding.ANSIX923(8).padder()
    text = bytes(initial_file, 'UTF-8')
    padded_text = padder.update(text) + padder.finalize()
    iv = os.urandom(8)  # случайное значение для инициализации блочного режима,
    # должно быть размером с блок и каждый раз новым
    cipher = Cipher(algorithms.IDEA(decrypt_symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    c_text = encryptor.update(padded_text) + encryptor.finalize()
    with open(path_to_encrypt_file + os.sep + "encrypted_file.txt", "wb") as file:
        file.write(c_text)


