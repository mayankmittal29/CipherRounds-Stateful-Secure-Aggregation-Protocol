from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import hashlib
import hmac

BLOCK_SIZE = 16

def manual_pkcs7_pad(data):
    residual = len(data) % BLOCK_SIZE

    pad_len = BLOCK_SIZE if residual == 0 else (BLOCK_SIZE - residual)
    
    for i in range(pad_len):
        data += pad_len.to_bytes(1, 'big')

    return data

def manual_pkcs7_unpad(padded_data):
    pad_len = padded_data[len(padded_data)-1]
    
    if pad_len <= 0 or pad_len > BLOCK_SIZE:
        return -1
    
    data_length = len(padded_data) - pad_len

    for i in range(len(padded_data)-1, data_length-1, -1):
        if padded_data[i] != pad_len:
            return -1
        
    return padded_data[:data_length]

def aes_encrypt(key, plaintext, iv):
    padded_data = manual_pkcs7_pad(plaintext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_data)
    
    return ciphertext

def aes_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    padded_plaintext = cipher.decrypt(ciphertext)
    
    plaintext = manual_pkcs7_unpad(padded_plaintext)
    if plaintext == -1:
        raise ValueError("Padding validation failed.")
        
    return plaintext

def compute_hash(data):
    return hashlib.sha256(data).digest()

def compute_hmac(key, message):
    return hmac.new(key, message, hashlib.sha256).digest()
