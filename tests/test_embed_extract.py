from stego.crypto import AESCipher
from stego.embedder import embed_message_into_image
from stego.extractor import extract_message_from_image
from PIL import Image
import os


def _create_test_image(path: str, size=(100, 100)):
    img = Image.new("RGB", size, color=(255, 255, 255))
    img.save(path)


def test_embed_and_extract(tmp_path):
    test_image = tmp_path / "original.png"
    stego_image = tmp_path / "stego.png"
    _create_test_image(test_image)

    message = b"secret message for test"
    embed_message_into_image(str(test_image), message, str(stego_image))
    extracted = extract_message_from_image(str(stego_image))
    assert extracted == message


def test_embed_fails_if_image_too_small(tmp_path):
    tiny_image = tmp_path / "tiny.png"
    stego_image = tmp_path / "stego.png"
    _create_test_image(tiny_image, size=(5, 5))  # Too small

    message = b"A" * 1024  # 1 KB

    try:
        embed_message_into_image(str(tiny_image), message, str(stego_image))
    except ValueError as e:
        assert "Image is too small" in str(e)
    else:
        assert False, "Expected ValueError for small image"
