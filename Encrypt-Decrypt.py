import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher:
    def __init__(self, key):
        self.key = hashlib.sha256(key.encode('utf-8')).digest()

    def encrypt(self, message):
        message = self._pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(message)).decode('utf-8')

    def decrypt(self, encrypted):
        encrypted = base64.b64decode(encrypted)
        iv = encrypted[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(encrypted[AES.block_size:])).decode('utf-8')

    def _pad(self, message):
        padding = AES.block_size - len(message) % AES.block_size
        return message + chr(padding) * padding

    def _unpad(self, message):
        padding = ord(message[-1])
        return message[:-padding]

# Example usage
key = 'my secret key'
message = 'hello world'

cipher = AESCipher(key)
encrypted = cipher.encrypt(message)
print(encrypted)

decrypted = cipher.decrypt(encrypted)
print(decrypted)