import os
import hmac
import time
import random
import string
import serial
import hashlib
from Crypto.Cipher import AES


def generate_totp(secret, interval=30, digits=6):
    key = bytes.fromhex(f'{secret}').ljust(64, b'\x00')
    counter = int(time.time() // interval)
    counter_bytes = counter.to_bytes(8, byteorder='big')
    hmac_sha = hmac.new(key, counter_bytes, hashlib.sha256).digest()

    offset = hmac_sha[-1] & 0x0F
    truncated_hash = hmac_sha[offset:offset + 4]
    code = int.from_bytes(truncated_hash, byteorder='big') & 0x7FFFFFFF

    return str(code % 10 ** digits).zfill(digits)


def hmac_sha256(key: bytes, message: bytes):
    return hmac.new(key, message, hashlib.sha256).digest()


def pad16(data: bytes):
    """Дополняет данные до кратности 16 байт (PKCS#7)."""
    padding_len = 16 - (len(data) % 16)
    return data + bytes([padding_len] * padding_len)


def encrypt_aes128_ecb(key_16_bytes: bytes, data: bytes) -> bytes:
    cipher = AES.new(key_16_bytes, AES.MODE_ECB)
    return cipher.encrypt(pad16(data))


def send_encrypted_key(ser, aes_key_16b, secret):
    """Шифрует и отправляет ключ микроконтроллеру"""
    plaintext_key = bytes.fromhex(secret)
    encrypted_key = encrypt_aes128_ecb(aes_key_16b, plaintext_key)
    ser.write(f'SET_KEY {encrypted_key.hex()}\r\n'.encode())
    response = ser.readline().decode().strip()
    return response == 'KEY_OK'


def main():
    # Секрет и AES-ключ (оба в hex)
    # Генерация нового 128-битного секрета
    secret_bytes = os.urandom(16)
    secret = secret_bytes.hex()
    print(f'Сгенерированный секрет: {secret}')

    aes_key_hex = "00112233445566778899aabbccddeeff"
    aes_key = bytes.fromhex(aes_key_hex)
    ser = None

    try:
        ser = serial.Serial('COM17', baudrate=112500, timeout=10)
        print(f'Подключено к {ser.name}')

        ser.write(b'CHECK_KEY\r\n')
        response = ser.readline().decode().strip()

        if response == 'KEY_NOT_FOUND':
            print('Ключ не найден. Отправка зашифрованного ключа...')
            if not send_encrypted_key(ser, aes_key, secret):
                print('Ошибка: микроконтроллер не подтвердил получение ключа.')
                return
            print('Ключ успешно установлен.')

        # Установка времени
        ser.write(f"SET_TIME {int(time.time())}\r\n".encode())
        response = ser.readline().decode().strip()
        print(f'Ответ на SET_TIME: {response}')

        # Проверка TOTP
        ser.write(b"GET_TOTP\r\n")
        totp_from_controller = ser.readline().decode().strip()
        totp_from_server = generate_totp(secret)

        print(f'TOTP от контроллера: {totp_from_controller}')
        print(f'TOTP от сервера:     {totp_from_server}')

        if totp_from_server != totp_from_controller:
            print('Ошибка: TOTP не совпадает.')
            ser.write(b"SET_RED\r\n")
            return

        # Challenge-Response
        challenge = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        ser.write(f"GET_HMAC {challenge}\r\n".encode())
        challenge_from_controller = ser.readline().decode()
        key_bytes = bytes.fromhex(secret)
        challenge_from_server = hmac_sha256(key_bytes, challenge.encode())

        if challenge_from_server.hex() != challenge_from_controller:
            print('Ошибка: Challenge не совпадает.')
            ser.write(b"SET_RED\r\n")
            return

        print('Доступ разрешен!')
        ser.write(b"SET_GREEN\r\n")

    except Exception as e:
        print(f'Ошибка: {e}')

    finally:
        if ser and ser.is_open:
            ser.close()
            print('Соединение закрыто.')

        input('\nНажмите Enter для выхода...')


if __name__ == '__main__':
    main()
