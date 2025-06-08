import socket
import random


def diffie_hellman_server():
    # Общеизвестные параметры (обычно большие простые числа)
    p = 23  # простое число
    g = 5  # первообразный корень по модулю p

    # Создаем сокет
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)

    print("Сервер ожидает подключения...")
    conn, addr = server_socket.accept()
    print(f"Подключен клиент: {addr}")

    # Получаем A от клиента
    A = int(conn.recv(1024).decode())
    print(f"Получено A от клиента: {A}")

    # Генерируем секретное число b и вычисляем B
    b = random.randint(1, p - 1)
    B = pow(g, b, p)
    print(f"Сгенерировано секретное число b: {b}")
    print(f"Вычислено B: {B}")

    # Отправляем B клиенту
    conn.send(str(B).encode())

    # Вычисляем общий секрет K
    K = pow(A, b, p)
    print(f"Общий секрет K: {K}")

    conn.close()
    server_socket.close()


if __name__ == "__main__":
    diffie_hellman_server()