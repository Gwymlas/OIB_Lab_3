import argparse
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as pad_asym
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
import json
import os
import pickle
from tqdm import tqdm

with open('settings.json') as json_file:
    json_data = json.load(json_file)

path_initial_file = json_data["initial_file"]
path_encrypted_file = json_data["encrypted_file"]
path_decrypted_file = json_data["decrypted_file"]
path_symmetric_key = json_data["symmetric_key"]
path_public_key = json_data["public_key"]
path_secret_key = json_data["secret_key"]


def key_generation(path_to_symmetric_key: str, path_to_public_key: str, path_to_secret_key: str) -> None:
    """
    Функция создает симметричный ключ для шифрования текст и пару ключей(public, private) для передачи симметричный ключ
    и зашифровывает ключ симметричного шифрования открытым ключом

    :param path_to_symmetric_key: путь сохранения зашифрованного симметричного ключа
    :param path_to_public_key: путь сохранения публичного ключа ассиметричного алгоритма
    :param path_to_secret_key: путь сохранения приватного ключа ассиметричного алгоритма
    :return: None
    """
    symmetric_key = algorithms.IDEA(os.urandom(16))
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = rsa_key
    public_key = rsa_key.public_key()
    with open(path_to_public_key, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(path_to_secret_key, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))
    encrypt_symmetric_key = public_key.encrypt(symmetric_key.key,
                                               pad_asym.OAEP(mgf=pad_asym.MGF1(algorithm=hashes.SHA256()),
                                                             algorithm=hashes.SHA256(), label=None))
    with open(path_to_symmetric_key, 'wb') as symmetric_out:
        symmetric_out.write(encrypt_symmetric_key)


def encrypt_file(path_to_initial_file: str, path_to_secret_key: str, path_to_symmetric_key: str,
                 path_to_encrypt_file: str) -> None:
    """
    Это функция зашифровывает текст симметричным алгоритмом

    :param path_to_initial_file: путь к шифруемому текстовому файлу
    :param path_to_secret_key: путь к закрытому ключу ассиметричного алгоритма
    :param path_to_symmetric_key: путь к зашированному ключу симметричного алгоритма
    :param path_to_encrypt_file: путь, по которому сохранить зашифрованный текстовый файл
    :return: None
    """
    with open(path_to_symmetric_key, mode='rb') as key_file:
        encrypt_symmetric_key = key_file.read()

    with open(path_to_secret_key, 'rb') as pem_in:
        private_bytes = pem_in.read()
    d_private_key = load_pem_private_key(private_bytes, password=None)

    decrypt_symmetric_key = d_private_key.decrypt(encrypt_symmetric_key,
                                                  pad_asym.OAEP(mgf=pad_asym.MGF1(algorithm=hashes.SHA256()),
                                                                algorithm=hashes.SHA256(), label=None))

    with open(path_to_initial_file, 'r', encoding='utf-8') as file:
        initial_file = file.read()

    padder = padding.ANSIX923(64).padder()
    text = bytes(initial_file, 'UTF-8')
    padded_text = padder.update(text) + padder.finalize()
    iv = os.urandom(8)  # случайное значение для инициализации блочного режима,
    # должно быть размером с блок и каждый раз новым
    cipher = Cipher(algorithms.IDEA(decrypt_symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypt_text = encryptor.update(padded_text) + encryptor.finalize()
    data = {"iv": iv, "encrypt_text": encrypt_text}
    with open(path_to_encrypt_file, "wb") as file:
        pickle.dump(data, file)


def decrypt_file(path_to_encrypt_file: str, path_to_secret_key: str, path_to_symmetric_key: str,
                 path_to_decrypted_file: str):
    """
    Функция расшифровывает текст симметричным алгоритмом и сохранить по указанному пути
    :param path_to_encrypt_file: путь к зашифрованному текстовому файлу
    :param path_to_secret_key: путь к закрытому ключу ассиметричного алгоритма
    :param path_to_symmetric_key: путь к зашированному ключу симметричного алгоритма
    :param path_to_decrypted_file: путь, по которому сохранить расшифрованный текстовый файл
    :return: None
    """
    with open(path_to_symmetric_key, mode='rb') as key_file:
        encrypt_symmetric_key = key_file.read()

    with open(path_to_secret_key, 'rb') as pem_in:
        private_bytes = pem_in.read()
    d_private_key = load_pem_private_key(private_bytes, password=None)

    decrypt_symmetric_key = d_private_key.decrypt(encrypt_symmetric_key,
                                                  pad_asym.OAEP(mgf=pad_asym.MGF1(algorithm=hashes.SHA256()),
                                                                algorithm=hashes.SHA256(), label=None))

    with open(path_to_encrypt_file, "rb") as file:
        data = pickle.load(file)

    iv = data["iv"]
    encrypt_text = data["encrypt_text"]
    cipher = Cipher(algorithms.IDEA(decrypt_symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypt_text = decryptor.update(encrypt_text) + decryptor.finalize()

    unpadder = padding.ANSIX923(64).unpadder()
    unpadded_decrypt_text = unpadder.update(decrypt_text) + unpadder.finalize()
    with open(path_to_decrypted_file, 'w', encoding='utf-8') as file:
        file.write(str(unpadded_decrypt_text.decode("utf-8")))


parser = argparse.ArgumentParser(description="main.py")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-gen', '--generation', help='Запускает режим генерации ключей')
group.add_argument('-enc', '--encryption', help='Запускает режим шифрования')
group.add_argument('-dec', '--decryption', help='Запускает режим дешифрования')

args = parser.parse_args()
if args.generation is not None:
    with tqdm(100, desc="Process of key generation") as pbar:
        key_generation(path_symmetric_key, path_public_key, path_secret_key)
        pbar.update(100)
elif args.encryption is not None:
    with tqdm(100, desc="Process of encrypting a file") as pbar:
        encrypt_file(path_initial_file, path_secret_key, path_symmetric_key, path_encrypted_file)
        pbar.update(100)
else:
    with tqdm(100, desc="Process of decrypting a file") as pbar:
        decrypt_file(path_encrypted_file, path_secret_key, path_symmetric_key, path_decrypted_file)
        pbar.update(100)
