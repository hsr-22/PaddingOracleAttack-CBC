from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

KEY_LENGTH = 16  # AES128
BLOCK_SIZE = (algorithms.AES.block_size)//8
AES = algorithms.AES
CBC = modes.CBC

_backend = default_backend()
_key = os.urandom(KEY_LENGTH)


def _add_padding(msg):
	pad_len = BLOCK_SIZE - (len(msg) % BLOCK_SIZE)
	padding = bytes([pad_len]) * pad_len
	return msg + padding


def _remove_padding(data):
	pad_len = data[-1]
	
	if pad_len < 1 or pad_len > BLOCK_SIZE:
		return None
	for i in range(1, pad_len):
		if data[-i-1] != pad_len:
			return None
	return data[:-pad_len]


def encrypt(msg):
    iv = os.urandom(BLOCK_SIZE)
    cipher = Cipher(AES(_key), CBC(iv), _backend)
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(_add_padding(msg)) + encryptor.finalize()
    return iv + ciphertext


def _decrypt(data):
    iv = data[:BLOCK_SIZE]
    cipher = Cipher(AES(_key), CBC(iv), _backend)
    decryptor = cipher.decryptor()

    decrypted = decryptor.update(data[BLOCK_SIZE:]) + decryptor.finalize()
    return _remove_padding(decrypted)


def is_padding_ok(data):
	return _decrypt(data) is not None


if __name__ == '__main__':
	#print("decrypted message:", _decrypt( ciphertext ) )
	print(BLOCK_SIZE)
	print("USE attack.py!!")