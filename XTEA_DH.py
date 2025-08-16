import random
import hashlib
from time import sleep
import os

p = 23
g = 5

RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
RESET = "\033[0m"
BOLD = "\033[1m"
UNDER = "\033[4m"
MAGENTA = "\033[35m"

# will be used for Alice and Bob
def generate_keys(p, g):
    private_key = random.randint(2, p-1)  # private key
    # Generate public key using g^private_key % p
    public_key = pow(g, private_key, p)
    return private_key, public_key

def calc_shared_secret(private_key, received_public_key, p):
    # Compute the shared secret using received public key
    shared_secret = pow(received_public_key, private_key, p)
    return shared_secret

def write_public_space(filename, data):
    with open(filename, 'w') as f:
        f.write(str(data))

def read_public_space(filename):
    with open(filename, 'r') as f:
        data = f.read()
    return int(data)

def derive_key(shared_secret):
    # hash shared secret to create a 128-bit key for xtea
    return hashlib.sha256(str(shared_secret).encode()).digest()[:16]

def generate_iv():
    return os.urandom(8)

def xtea_encrypt(plaintext, key, iv):
    def xtea_encrypt_block(v, k):
        v0, v1 = int.from_bytes(v[:4], 'big'), int.from_bytes(v[4:], 'big')
        sum, delta, mask = 0, 0x9E3779B9, 0xFFFFFFFF
        for _ in range(32):
            v0 = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
            sum = (sum + delta) & mask
            v1 = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
        return v0.to_bytes(4, 'big') + v1.to_bytes(4, 'big')

    k = [int.from_bytes(key[i:i+4], 'big') for i in range(0, 16, 4)]
    ofb_block = iv
    ciphertext = b''
    for i in range(0, len(plaintext), 8):
        ofb_block = xtea_encrypt_block(ofb_block, k)
        plaintext_block = plaintext[i:i+8].ljust(8, b'\x00') #8 long, justify to the left
        ciphertext += bytes(a ^ b for a, b in zip(plaintext_block, ofb_block))
    return ciphertext

def xtea_decrypt(ciphertext, key, iv):
    return xtea_encrypt(ciphertext, key, iv)  # OFB mode: same proccess

def encrypt_message(plaintext_message, key):
    if isinstance(plaintext_message, str):
        plaintext_message = plaintext_message.encode()
    iv = generate_iv() #generate initial vector each time we send a message
    padded_message = pad(plaintext_message, 8)
    encrypted_message = xtea_encrypt(padded_message, key, iv)
    return iv.hex() + encrypted_message.hex()

def decrypt_message(encrypted_message, key):
    encrypted_data = bytes.fromhex(encrypted_message)
    iv, ciphertext = encrypted_data[:8], encrypted_data[8:]
    decrypted_data = xtea_decrypt(ciphertext, key, iv)
    original_data = unpad(decrypted_data)
    return original_data.decode()

def pad(data, block_size):
    if isinstance(data, str):
        data = data.encode()
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

if __name__ == "__main__":
    sleep_time= 0;
    # key exchange using DH
    print(f"{BLUE}{UNDER}alice and bob perform DH key exchange{RESET}")
    sleep(sleep_time)
    alice_private, alice_public = generate_keys(p, g)
    bob_private, bob_public = generate_keys(p, g)
    
    print(f"alice's public key: {alice_public}")
    print(f"bob's public key: {bob_public}")

    sleep(sleep_time)



    # calculate shared key
    print(f"\n{BLUE}{UNDER}calculating shared secret...{RESET}")
    alice_shared_secret = calc_shared_secret(alice_private, bob_public, p)
    bob_shared_secret = calc_shared_secret(bob_private, alice_public, p)

    sleep(sleep_time)


    
    assert alice_shared_secret == bob_shared_secret, "shared secrets don't match!"
    print(f"shared secret: {alice_shared_secret}")

    sleep(sleep_time)



    # symmetric key from shared secret
    symmetric_key = derive_key(alice_shared_secret)
    print(f"symmetric key derived {symmetric_key.hex()}")

    sleep(sleep_time)



   # alice generates the XTEA key, encrypts it, and sends it to bob
    print(f"\n{BLUE}{UNDER}alice generates and encrypts XTEA key{RESET}")
    xtea_key = b'password12345678'  # 128-bit key
    encrypted_xtea_key = encrypt_message(xtea_key, symmetric_key)
    print(f"alice's encrypted XTEA key: {encrypted_xtea_key}")

    sleep(sleep_time)



     # bob, using the shared key, decrypts the XTEA key
    print(f"\n{BLUE}{UNDER}bob decrypts the XTEA key{RESET}")
    decrypted_xtea_key = decrypt_message(encrypted_xtea_key, symmetric_key).encode()
    print(f"bob's decrypted XTEA key: {decrypted_xtea_key.decode()}")
    
    sleep(sleep_time)



    assert xtea_key == decrypted_xtea_key, "XTEA key decryption failed!"

    # alice sends, using XTEA, an encrypted message to bob
    print(f"\n{BLUE}{UNDER}alice encrypts a message using XTEA{RESET}")
    alice_message = "hello bob can you see my message?\n\tsend me a message when you recieve this message.\n\t\t thanks, alice."
    print(f"\nalice's plaintext message:\n{MAGENTA}{BOLD} {alice_message}{RESET}")
    sleep(sleep_time)
    encrypted_message = encrypt_message(alice_message, xtea_key)
    print(f"\nalice's encrypted message:\n{encrypted_message}")

    sleep(sleep_time)



     # bob, using the decrypted XTEA key, decrypts alice's message
    print(f"\n{BLUE}{UNDER}bob decrypts alice's message{RESET}")
    decrypted_message = decrypt_message(encrypted_message, decrypted_xtea_key)
    print(f"\nbob's decrypted message:\n{GREEN}{BOLD}{decrypted_message}{RESET}")

    sleep(sleep_time)



    assert alice_message == decrypted_message, "message decryption failed!"
    print(f"\n{BOLD}success, alice_message == decrypted_message{RESET}")
