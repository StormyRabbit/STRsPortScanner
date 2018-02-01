from Crypto.Cipher import AES
import hashlib
from Crypto import Random

class EncryptionMgr:

    def __init__(self):
        self.isKeyLoaded = False
        self.loadedKey = None
        self.encrypted_data = None

    @staticmethod
    def _pad_input(msg):
        while len(msg) % 16 != 0:
            msg += b"0"
        return msg

    @staticmethod
    def create_key_file(key, key_file_name):
        padded_key = hashlib.sha256(key.encode()).digest()
        with open(key_file_name, 'wb') as f:
            f.write(padded_key)

    @staticmethod
    def write_encrypted_to_file(encrypted_data, file_name):
        with open(file_name, 'wb') as f:
            f.write(encrypted_data)

    def load_key_file(self, file_name):
        with open(file_name, 'rb') as f:
            self.loadedKey = f.read()
        self.isKeyLoaded = True

    def save_with_key_file(self, file_name, data):
        if self.loadedKey:
            iv = Random.new().read(AES.block_size)
            encryption_box = AES.new(self.loadedKey, AES.MODE_CBC, iv)
            encrypted_data = encryption_box.encrypt(self._pad_input(data))
            with open(file_name, 'wb') as f:
                f.write(iv + encrypted_data)

    def encrypt(self, msg, key):
        test = self._pad_input(msg)
        padded_key = hashlib.sha256(key.encode()).digest()
        iv = Random.new().read(AES.block_size)
        encryption_box = AES.new(padded_key, AES.MODE_CBC, iv)
        encrypted_data = encryption_box.encrypt(test)
        return iv + encrypted_data

    def load_encrypted_file(self, file_name):
        with open(file_name, 'rb') as f:
            self.encrypted_data = f.read()

    @staticmethod
    def decrypt(encrypted_data, key):
        iv = encrypted_data[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_msg = cipher.decrypt(encrypted_data[AES.block_size:]).decode('utf-8')
        msg = decrypted_msg.strip('0')
        return msg

    @staticmethod
    def create_rnd_key_file(file_name):
        k = Random.new().read(32)
        with open(file_name, 'wb') as f:
            f.write(k)
