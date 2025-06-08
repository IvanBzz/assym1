import os
import pickle
from pathlib import Path


def generate_and_save_keys(filename="keys.pkl"):
    p = 23  # В реальной системе должно быть большим простым числом
    g = 5  # Первообразный корень по модулю p
    a = os.urandom(16).hex()  # Секретный ключ
    A = pow(g, int(a, 16), p)  # Публичный ключ

    keys = {'p': p, 'g': g, 'private': a, 'public': A}

    with open(filename, 'wb') as f:
        pickle.dump(keys, f)

    return keys


def load_keys(filename="keys.pkl"):
    if not Path(filename).exists():
        return generate_and_save_keys(filename)

    with open(filename, 'rb') as f:
        return pickle.load(f)