from stego.crypto import AESCipher


def test_encrypt_decrypt_basic():
    aes = AESCipher("strongpass123")
    message = b"this is a test message"
    encrypted = aes.encrypt(message)
    decrypted = aes.decrypt(encrypted)
    assert decrypted == message


def test_encrypt_produces_different_outputs():
    aes = AESCipher("strongpass123")
    message = b"same message"
    ciphertext1 = aes.encrypt(message)
    ciphertext2 = aes.encrypt(message)
    assert ciphertext1 != ciphertext2  # Due to random IV
