import os
import sys
import platform
import json
import base64
import shutil
import sqlite3
from Crypto.Cipher import AES
import win32crypt
from contextlib import closing

file = "chrome_passwords.txt"  # File to store Chrome plain passwords
file2 = "Loginvault.db"  # File to store Chrome encrypted passwords

OS = [
    {
        "Windows": {
            "Chrome": {
                "basepath": os.path.join(os.path.expanduser("~"), "AppData\\Local\\Google\\Chrome\\User Data"),
                "key_path": "Local State",
                "passwords_path": "Default\\Login Data"
            },
        }
    },
    {
        "Mac": {
            "Chrome": {
                "basepath": "~/Library/Application Support/Google/Chrome/(Default|{PROFILE})/Login Data",
            }
        }
    },
]


def get_secret_key():
    os_name = platform.system()
    for system in OS:
        try:
            file = os.path.join(
                system[os_name]["Chrome"]["basepath"], system[os_name]["Chrome"]["key_path"])
            with open(file, "r", encoding="latin1") as f:
                secret_key = base64.b64decode(
                    json.load(f)["os_crypt"]["encrypted_key"])[5:]
                secret_key = win32crypt.CryptUnprotectData(
                    secret_key, None, None, None, 0)[1]
            return secret_key, system[os_name]["Chrome"]
        except:
            pass
    sys.exit("Your OS is not supported!")


def decrypt_passwords(secret_key, system):
    shutil.copy2(os.path.join(
        system["basepath"], system["passwords_path"]), file2)

    with closing(sqlite3.connect(file2)) as conn:
        with closing(conn.cursor()) as cursor:
            cursor.execute(
                "SELECT signon_realm, username_value, password_value FROM logins")
            decrypted_passwords = []

            for _index, login in enumerate(cursor.fetchall()):
                if login:
                    decrypted_passwords.append(
                        {"Hostname": login[0], "Username": login[1], "Password": decrypt(secret_key, login[2])})
    return decrypted_passwords


def decrypt(secret_key, cipher_text):
    initialization_vector = cipher_text[3:15]
    encrypted_password = cipher_text[15:-16]
    cipher = AES.new(secret_key, AES.MODE_GCM, initialization_vector)
    decrypted_password = cipher.decrypt(encrypted_password).decode("latin1")
    return decrypted_password


def display_plain_data(decrypted_data):
    for data in decrypted_data:
        print("Hostname: "
              + data["Hostname"]
              + "\nUsername: "
              + data["Username"]
              + "\nPassword: "
              + data["Password"]
              + "\n"
              )


def store_plain_data(decrypted_data):
    with open(file, "w") as f:
        f.write(json.dumps(decrypted_data, indent=4))
    print("Chrome passwords saved in " + file)


if __name__ == "__main__":
    secret_key, system = get_secret_key()
    decrypted_passwords = decrypt_passwords(secret_key, system)
    display_plain_data(decrypted_passwords)
    store_plain_data(decrypted_passwords)

    input() # To keep the window open at the end of the program
