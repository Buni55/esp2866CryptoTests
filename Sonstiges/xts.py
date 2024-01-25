from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(24)
plaintext = b"HelloWorldBunyam"

cipher = AES.new(key, AES.MODE_XTS)




print(key)
