import socket
import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import os
from cryptography.hazmat.primitives import serialization


# Добавить эти функции в начало файла:
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


# Модифицировать функцию запуска сервера:
def start_server():
    KEY_DIR = 'server_keys'
    os.makedirs(KEY_DIR, exist_ok=True)

    # Загрузка или генерация ключей
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



ALLOWED_CLIENTS_DIR = 'allowed_clients'
os.makedirs(ALLOWED_CLIENTS_DIR, exist_ok=True)

def is_client_allowed(pub_key_bytes):
    for filename in os.listdir(ALLOWED_CLIENTS_DIR):
        if filename.endswith('.pem'):
            with open(os.path.join(ALLOWED_CLIENTS_DIR, filename), 'rb') as f:
                if f.read() == pub_key_bytes:
                    return True
    return False



def generate_dh_parameters():
    # Генерация параметров DH
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters


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


def asymmetric_server():
    # Генерация параметров DH
    parameters = generate_dh_parameters()

    # Генерация ключевой пары сервера
    server_private_key, server_public_key = generate_dh_key_pair(parameters)

    # Создание сокета
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)

    print("Сервер ожидает подключения...")
    conn, addr = server_socket.accept()
    print(f"Подключен клиент: {addr}")

    try:
        # Отправка параметров DH клиенту
        conn.send(parameters.parameter_bytes(encoding='PEM', format='PKCS3'))

        # Получение публичного ключа клиента
        client_public_key_bytes = conn.recv(4096)
        client_public_key = dh.DHPublicKey.from_encoded_parameters(
            parameters=parameters,
            encoding=client_public_key_bytes,
            format='SubjectPublicKeyInfo'
        )

        # Отправка публичного ключа сервера клиенту
        conn.send(server_public_key.public_bytes(
            encoding='PEM',
            format='SubjectPublicKeyInfo'
        ))

        # Вычисление общего ключа
        shared_key = derive_shared_key(server_private_key, client_public_key)
        print("Общий ключ установлен")

        # Получение зашифрованного сообщения
        encrypted_msg = conn.recv(4096)
        decrypted_msg = decrypt_message(shared_key, encrypted_msg)
        print(f"Получено сообщение: {decrypted_msg.decode()}")

        # Отправка ответа
        response = b"Hello from server!"
        encrypted_response = encrypt_message(shared_key, response)
        conn.send(encrypted_response)

        client_pub_key = conn.recv(4096)  # Получаем ключ клиента
        if not is_client_allowed(client_pub_key):
            conn.send(b'ACCESS_DENIED')
            conn.close()
            return

    finally:
        conn.close()
        server_socket.close()


if __name__ == "__main__":
    asymmetric_server()