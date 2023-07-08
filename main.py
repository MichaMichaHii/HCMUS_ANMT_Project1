import sys
from Modules import *
import glob
import os
import json

choice = input("Chon (E)ncrypted de ma hoa hoac (D)ecrypted de giai ma: ")
if (choice != "E" and choice != "D" and choice != "e" and choice != "d"):
    print("Error")
    sys.exit()
elif (choice == "E" or choice == "e"):
    choice = input("Ban muon generate 1 key khong ? (Y/N): ")  # khong can generate 1 key neu ban muon giai ma 1 file
    if (choice != "Y" and choice != "y" and choice != "N" and choice != "n"):
        print("Error")
        sys.exit()
    elif (choice == "Y" or choice == "y"):
        key_size = int(input("Ban muon key bao nhieu bytes(16/32) ? "))
        key = generate_aes_key(key_size)
        choice = input("Ban muon in key ra man hinh khong (khuyen khich in ra va luu lai key o 1 noi an toan) ? (Y/N) ")
        if (choice != "Y" and choice != "y" and choice != "N" and choice != "n"):
            print("Error")
            sys.exit()
        elif (choice == "Y" or choice == "y"):
            print(key)
            print("Ban nen luu lai key cua minh vao mot noi an toan nhe")
        # Hệ thống phát sinh cặp khoá Kprivate và Kpublic của thuật toán RSA và mã hoá khoá Ks bằng khoá Kpublic, output là chuỗi Kx.
        n, public_key, private_key = set_keys()
        Kx = encrypt_message((str(key))[2:-1], public_key, n)
        HKprivate = hash_sha1_calculate(str(private_key))
        data = {
            "Kx": Kx,
            "hkprivate": HKprivate,
            "n": n,
        }
        print("Kprivate: " + str(private_key))
        choice = input("Ban co muon luu khoa Kprivate vao 1 file text khong? (Y/N): ")
        if (choice != "Y" and choice != "y" and choice != "N" and choice != "n"):
            print("Error")
            sys.exit()
        elif (choice == "Y" or choice == "y"):
            with open("KPrivate.txt", "w") as file:
                file.write(str(private_key))

    file_path = input("Nhap duong dan file can ma hoa: ")
    encrypt_file(file_path, key)
    print("File da ma hoa thanh cong")
    filename = os.path.basename(file_path)
    with open(f"{filename}.metadata.json", "w") as file:
        json.dump(data, file, indent=8)

elif (choice == "D" or choice == "d"):
    encrypted_file_path = input("Nhap duong dan file can ma hoa: ")
    choice = input("Ban muon nhap key hay chon tu file? (K)eyboard/(F)ile: ")
    if (choice != "F" and choice != "f" and choice != "K" and choice != "k"):
        print("Error")
        sys.exit()
    elif (choice == "K" or choice == "k"):
        Kprivate_input = input("Nhap key: ")
        HKprivate_input = hash_sha1_calculate(str(Kprivate_input))
        json_files = glob.glob("**/*.json", recursive=True)
        for json_file in json_files:
            with open(json_file, "r") as file:
                HKprivate = json.load(file)
                if "hkprivate" in HKprivate and HKprivate["hkprivate"] == str(HKprivate_input):
                    # Giải mã chuỗi Kx để có được Ks dùng Kprivate.
                    Ks = decrypt_message(HKprivate["Kx"], int(Kprivate_input), int(HKprivate["n"]))
                    Ks = Ks.encode('utf-8').decode('unicode_escape').encode('latin-1')
                    decrypt_file(encrypted_file_path,Ks)
                else:
                    print("Khoa sai")
                    sys.exit()
    elif (choice == "F" or choice == "f"):
        filepath = input("Nhap duong dan file: ")
        with open(filepath,'r') as file:
            Kprivate_input = file.read()
            Kprivate_input = int(Kprivate_input)
        HKprivate_input = hash_sha1_calculate(str(Kprivate_input))
        json_files = glob.glob("**/*.json", recursive=True)
        for json_file in json_files:
            with open(json_file, "r") as file:
                HKprivate = json.load(file)
                if "hkprivate" in HKprivate and HKprivate["hkprivate"] == str(HKprivate_input):
                    # Giải mã chuỗi Kx để có được Ks dùng Kprivate.
                    Ks = decrypt_message(HKprivate["Kx"], int(Kprivate_input), int(HKprivate["n"]))
                    Ks = Ks.encode('utf-8').decode('unicode_escape').encode('latin-1')
                    decrypt_file(encrypted_file_path,Ks)
                else:
                    print("Khoa sai")
                    sys.exit()

