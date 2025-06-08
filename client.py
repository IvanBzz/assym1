import socket
import random


def diffie_hellman_client():
    # Общеизвестные параметры (должны совпадать с сервером)
    p = 23  # простое число
    g = 5  # первообразный корень по модулю p

    # Создаем сокет и подключаемся к серверу
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    # Генерируем секретное число a и вычисляем A
    a = random.randint(1, p - 1)
    A = pow(g, a, p)
    print(f"Сгенерировано секретное число a: {a}")
    print(f"Вычислено A: {A}")

    # Отправляем A серверу
    client_socket.send(str(A).encode())

    # Получаем B от сервера
    B = int(client_socket.recv(1024).decode())
    print(f"Получено B от сервера: {B}")

    # Вычисляем общий секрет K
    K = pow(B, a, p)
    print(f"Общий секрет K: {K}")

    client_socket.close()


if __name__ == "__main__":
    diffie_hellman_client()