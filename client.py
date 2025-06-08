import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from cryptography.hazmat.primitives import serialization


def save_key_to_file(key, filename, private=False):
    """Сохраняет ключ в файл"""
    if private:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(filename, 'wb') as f:
        f.write(pem)

def load_key_from_file(filename, private=False, parameters=None):
    """Загружает ключ из файла"""
    with open(filename, 'rb') as f:
        pem = f.read()
    if private:
        return serialization.load_pem_private_key(pem, password=None, backend=default_backend())
    else:
        if parameters:
            return dh.DHPublicKey.from_encoded_parameters(parameters, pem, 'SubjectPublicKeyInfo')
        return serialization.load_pem_public_key(pem, backend=default_backend())


def start_client():
    KEY_DIR = 'client_keys'
    os.makedirs(KEY_DIR, exist_ok=True)

    if os.path.exists(f'{KEY_DIR}/private_key.pem'):
        with open(f'{KEY_DIR}/dh_params.pem', 'rb') as f:
            parameters = serialization.load_pem_parameters(f.read())
        private_key = load_key_from_file(f'{KEY_DIR}/private_key.pem', private=True)
        public_key = load_key_from_file(f'{KEY_DIR}/public_key.pem')
    else:
        parameters = generate_dh_parameters()
        private_key, public_key = generate_dh_key_pair(parameters)
        save_key_to_file(private_key, f'{KEY_DIR}/private_key.pem', private=True)
        save_key_to_file(public_key, f'{KEY_DIR}/public_key.pem')




def generate_dh_key_pair(parameters):
    # Генерация ключевой пары
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


def derive_shared_key(private_key, peer_public_key):
    # Вычисление общего секрета
    shared_key = private_key.exchange(peer_public_key)

    # Производный ключ для шифрования
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    return derived_key


def encrypt_message(key, message):
    # Шифрование сообщения
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv + ciphertext


def decrypt_message(key, ciphertext):
    # Дешифрование сообщения
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(actual_ciphertext) + decryptor.finalize()


def asymmetric_client():
    # Создание сокета и подключение к серверу
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    try:
        # Получение параметров DH от сервера
        parameters_bytes = client_socket.recv(4096)
        parameters = dh.DHParameters.from_pem(parameters_bytes)

        # Генерация ключевой пары клиента
        client_private_key, client_public_key = generate_dh_key_pair(parameters)

        # Отправка публичного ключа клиента серверу
        client_socket.send(client_public_key.public_bytes(
            encoding='PEM',
            format='SubjectPublicKeyInfo'
        ))

        # Получение публичного ключа сервера
        server_public_key_bytes = client_socket.recv(4096)
        server_public_key = dh.DHPublicKey.from_encoded_parameters(
            parameters=parameters,
            encoding=server_public_key_bytes,
            format='SubjectPublicKeyInfo'
        )

        # Вычисление общего ключа
        shared_key = derive_shared_key(client_private_key, server_public_key)
        print("Общий ключ установлен")

        # Отправка зашифрованного сообщения
        message = b"Hello from client!"
        encrypted_msg = encrypt_message(shared_key, message)
        client_socket.send(encrypted_msg)

        # Получение ответа от сервера
        encrypted_response = client_socket.recv(4096)
        decrypted_response = decrypt_message(shared_key, encrypted_response)
        print(f"Получен ответ: {decrypted_response.decode()}")

    finally:
        client_socket.close()


if __name__ == "__main__":
    asymmetric_client()