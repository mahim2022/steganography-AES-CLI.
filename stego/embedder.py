from PIL import Image
from typing import List


def _bytes_to_bits(data: bytes) -> List[int]:
    """Convert bytes to a list of individual bits."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _int_to_bytes(n: int, length: int = 4) -> bytes:
    """Convert an integer into a fixed-length bytes object."""
    return n.to_bytes(length, byteorder="big")


def embed_message_into_image(
    image_path: str,
    message: bytes,
    output_path: str,
) -> None:
    img = Image.open(image_path)
    img = img.convert("RGB")  # Make sure it's RGB
    pixels = list(img.getdata())

    message_len = len(message)
    header = _int_to_bytes(message_len, 4)  # 4-byte length = 32 bits
    full_message = header + message
    bits = _bytes_to_bits(full_message)

    required_pixels = (len(bits) + 2) // 3  # 3 bits per pixel (1 per RGB channel)
    if required_pixels > len(pixels):
        raise ValueError("Image is too small to hold the message.")

    new_pixels = []
    bit_idx = 0

    for pixel in pixels:
        r, g, b = pixel
        if bit_idx < len(bits):
            r = (r & 0xFE) | bits[bit_idx]
            bit_idx += 1
        if bit_idx < len(bits):
            g = (g & 0xFE) | bits[bit_idx]
            bit_idx += 1
        if bit_idx < len(bits):
            b = (b & 0xFE) | bits[bit_idx]
            bit_idx += 1
        new_pixels.append((r, g, b))

    # Append remaining pixels if we finished embedding early
    if len(new_pixels) < len(pixels):
        new_pixels.extend(pixels[len(new_pixels):])

    img.putdata(new_pixels)
    img.save(output_path)
