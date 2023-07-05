import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets

def generate_aes_key(size):
    sizeArr = [16,32]
    if(size not in sizeArr):
        return
    key_size = size
    key = secrets.token_bytes(key_size)
    return key

def encrypt_file(file_path, key):
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


def decrypt_file(file_path, key):
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



if __name__ == '__main__':
    choice = input("Ban muon generate 1 key khong ? (Y/N): ") #khong can generate 1 key neu ban muon giai ma 1 file
    if (choice != "Y" and choice != "y" and choice != "N" and choice != "n"):
        print("Error")
        sys.exit()
    elif (choice == "Y" or choice =="y"):
        key_size = int(input("Ban muon key bao nhieu bytes(16/32) ? "))
        key = generate_aes_key(key_size)
        choice = input("Ban muon in key ra man hinh khong (khuyen khich in ra va luu lai key o 1 noi an toan) ? (Y/N) ")
        if (choice != "Y" and choice != "y" and choice != "N" and choice != "n"):
            print("Error")
            sys.exit()
        elif (choice == "Y" or choice == "y"):
            print(key)
            print("Ban nen luu lai key cua minh vao mot noi an toan nhe")

    choice = input("Chon (E)ncrypted de ma hoa hoac (D)ecrypted de giai ma: ")
    if (choice != "E" and choice != "D" and choice != "e" and choice != "d"):
        print("Error")
        sys.exit()
    elif (choice == "E" or choice =="e"):
        file_path = input("Nhap duong dan file can ma hoa: ")
        encrypt_file(file_path, key)
        print("File da ma hoa thanh cong")
    elif (choice == "D" or choice =="d"):
        encrypted_file_path = input("Nhap duong dan file can ma hoa: ")
        key = input("Nhap key: ")
        key = key.encode('utf-8')
        key = bytes(key.decode('unicode_escape').encode('latin-1'))
        decrypt_file(encrypted_file_path, key)
        print("File da giai ma thanh cong")




