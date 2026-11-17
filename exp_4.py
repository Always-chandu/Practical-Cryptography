
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from os import urandom

# 1. Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()
print("RSA keys generated successfully.")

# 2. Create a sample file
with open("message.txt", "w") as f:
    f.write("This is a confidential message.")

# 3. Generate AES key and IV
aes_key = urandom(32)  # AES-256
iv = urandom(16)

# 4. Encrypt file using AES-CBC
with open("message.txt", "rb") as f:
    plaintext = f.read()

padder = sym_padding.PKCS7(128).padder()
padded_data = padder.update(plaintext) + padder.finalize()

encryptor = Cipher(
    algorithms.AES(aes_key), modes.CBC(iv)
).encryptor()

ciphertext = encryptor.update(padded_data) + encryptor.finalize()

with open("encrypted.bin", "wb") as f:
    f.write(iv + ciphertext)

# 5. Encrypt AES key using RSA-OAEP
encrypted_key = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

with open("aes_key.enc", "wb") as f:
    f.write(encrypted_key)

print("File and AES key encrypted successfully.")

# 6. Decrypt AES key using RSA private key
decrypted_key = private_key.decrypt(
    encrypted_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# 7. Decrypt the file
with open("encrypted.bin", "rb") as f:
    data = f.read()

iv = data[:16]
ciphertext = data[16:]

decryptor = Cipher(
    algorithms.AES(decrypted_key), modes.CBC(iv)
).decryptor()

padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

unpadder = sym_padding.PKCS7(128).unpadder()
original = unpadder.update(padded_plaintext) + unpadder.finalize()

with open("decrypted.txt", "wb") as f:
    f.write(original)

print("Decrypted message:", original.decode())
