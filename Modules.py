import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets
import random
from math import isqrt, gcd
import hashlib

def generate_aes_key(size): #module 1
    sizeArr = [16,32]
    if(size not in sizeArr):
        return
    key_size = size
    key = secrets.token_bytes(key_size)
    return key

def encrypt_file(file_path, key): #module 2
    block_size = algorithms.AES.block_size // 8

    # Đọc dữ liệu từ tập tin gốc
    with open(file_path, 'rb') as file:
        file_content = file.read()

    # Bổ sung dữ liệu để đảm bảo đủ kích thước khối
    padder = padding.PKCS7(block_size * 8).padder()
    padded_data = padder.update(file_content) + padder.finalize()

    # Tạo vector khởi tạo (initialization vector)
    iv = secrets.token_bytes(block_size)

    # Tạo đối tượng Cipher và thực hiện mã hoá
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Ghi dữ liệu đã mã hoá vào tập tin đích
    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(iv + encrypted_data)


def decrypt_file(file_path, key): #module 3
    block_size = algorithms.AES.block_size // 8

    # Đọc dữ liệu từ tập tin đã mã hoá
    with open(file_path, 'rb') as encrypted_file:
        encrypted_content = encrypted_file.read()

    # Tách IV và dữ liệu đã mã hoá
    iv = encrypted_content[:block_size]
    encrypted_data = encrypted_content[block_size:]

    # Tạo đối tượng Cipher và thực hiện giải mã
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Gỡ bỏ dữ liệu đã bổ sung
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    # Ghi dữ liệu đã giải mã vào tập tin đích
    decrypted_file_path = file_path + '.decrypted'
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)
    file_name = os.path.basename(decrypted_file_path)
    new_file_name = file_name.split(".")[0] + "." + file_name.split(".")[1]
    os.rename(decrypted_file_path, new_file_name)

# hàm khởi tạo cặp số nguyên tố
def generate_prime_pair(bit_length):
    p = random.getrandbits(bit_length) | 1
    q = random.getrandbits(bit_length) | 1
    while not is_prime(p) or not is_prime(q):
        p += 2
        q += 2
        if is_prime(p) and is_prime(q) and p != q:
            return p, q
    return generate_prime_pair(bit_length + 1)

# kiểm tra số nguyên tố
def is_prime(n):
    if n % 2 == 0 and n > 2:
        return False
    for i in range(3, isqrt(n) + 1, 2):
        if n % i == 0:
            return False
    return True

# tạo khóa public và khóa private (module 4)
def set_keys():
    prime1, prime2 = generate_prime_pair(8)
    n = prime1 * prime2
    fi = (prime1 - 1)*(prime2 - 1)
    e = 7
    while True: 
        if(gcd(e, fi) == 1):
            break
        e+=1
    public_key = e
    d = 2
    while True:
        if((d*e) % fi == 1):
            break
        d += 1
    private_key = d
    return n, public_key, private_key
# mã hóa chuỗi dùng thuật toán RSA với khóa public (module 5)
def encrypt_message(message, public_key, n):
    encrypted_message = ''
    for char in message:
        mess = ord(char)
        new_char = pow(mess, public_key, n)
        encrypted_message += chr(new_char)
    return encrypted_message

# giải mã chuỗi dùng thuật toán RSA với khóa private (module 6)
def decrypt_message(message, private_key, n):
    decrypted_message = ""
    for char in message:
        encrypt_char = ord(char)
        decrypt_char = pow(encrypt_char, private_key, n)
        decrypted_message += chr(decrypt_char)
    return decrypted_message
# tính hash của chuỗi với SHA-1 (module 7)
def hash_sha1_calculate(string):
    hasher = hashlib.sha1(string.encode('utf-8')).hexdigest()
    return hasher


