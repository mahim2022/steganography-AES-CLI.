from stego.crypto import AESCipher

password = "correct horse battery staple"
message = b"Hello, secret world!"

aes = AESCipher(password)

encrypted = aes.encrypt(message)
print(f"Encrypted: {encrypted.hex()}")

decrypted = aes.decrypt(encrypted)
print(f"Decrypted: {decrypted.decode()}")
