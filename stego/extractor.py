from PIL import Image
from typing import List


def _bits_to_bytes(bits: List[int]) -> bytes:
    """Convert a list of bits to bytes."""
    b = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        b.append(byte)
    return bytes(b)


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")


def extract_message_from_image(image_path: str) -> bytes:
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = list(img.getdata())

    bits = []

    for pixel in pixels:
        r, g, b = pixel
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)

    # Extract first 32 bits = 4 bytes = message length
    header_bits = bits[:32]
    header_bytes = _bits_to_bytes(header_bits)
    message_len = _bytes_to_int(header_bytes)

    total_message_bits = (message_len + 4) * 8  # 4 = header bytes
    if total_message_bits > len(bits):
        raise ValueError("Image does not contain enough data.")

    message_bits = bits[:total_message_bits]
    message_bytes = _bits_to_bytes(message_bits)

    return message_bytes[4:]  # exclude the 4-byte header
