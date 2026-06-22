import pytest
from cryptography.exceptions import InvalidTag

from aes_file_tool import FileFormatError, decrypt_bytes, encrypt_bytes


def test_encrypt_and_decrypt_text_file_content():
    plaintext = b"Mensaje de prueba para AES-256.\n"
    password = "clave segura"

    encrypted = encrypt_bytes(plaintext, password)
    decrypted = decrypt_bytes(encrypted, password)

    assert encrypted != plaintext
    assert decrypted == plaintext


def test_encrypt_and_decrypt_binary_file_content():
    plaintext = bytes(range(256)) + b"\x00\xff\x10binary-data"
    password = "otra clave segura"

    encrypted = encrypt_bytes(plaintext, password)
    decrypted = decrypt_bytes(encrypted, password)

    assert decrypted == plaintext


def test_wrong_password_fails():
    encrypted = encrypt_bytes(b"contenido secreto", "password correcta")

    with pytest.raises(InvalidTag):
        decrypt_bytes(encrypted, "password incorrecta")


def test_tampered_file_fails():
    encrypted = bytearray(encrypt_bytes(b"contenido secreto", "password correcta"))
    encrypted[-1] ^= 1

    with pytest.raises(InvalidTag):
        decrypt_bytes(bytes(encrypted), "password correcta")


def test_empty_file_roundtrip():
    encrypted = encrypt_bytes(b"", "password correcta")

    assert decrypt_bytes(encrypted, "password correcta") == b""


def test_invalid_header_fails():
    with pytest.raises(FileFormatError):
        decrypt_bytes(b"no-es-un-archivo-valido", "password")
