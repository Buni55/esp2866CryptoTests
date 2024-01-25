from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

salt = get_random_bytes(24)  # For AES-192 (24 bytes = 192 bits)
password = "password"
plaintext = b"Hello World"
iv = get_random_bytes(16) 

key = PBKDF2(password, salt, dkLen=24)
cipher = AES.new(key, AES.MODE_EAX, nonce=iv)

ciphertext, tag = cipher.encrypt_and_digest(pad(plaintext, AES.block_size))

print(f"\"key\" : \"{key.hex()}\"")
print(f"\"plaintext\" : \"{plaintext.hex()}\"")
print(f"\"ciphertext\" : \"{ciphertext.hex()}\"")
print(f"\"iv\" : \"{cipher.nonce.hex()}\"")
print(f"\"tag\" : \"{tag.hex()}\"")
