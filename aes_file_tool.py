import argparse
import getpass
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os


IDENTIFICADOR_ARCHIVO = b"AES256GCM"
VERSION = b"\x01"

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 390_000

HEADER_SIZE = len(IDENTIFICADOR_ARCHIVO) + len(VERSION) + SALT_SIZE + NONCE_SIZE


class FileFormatError(ValueError):
    pass


def derive_key(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password_bytes)


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(password, salt)

    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    return IDENTIFICADOR_ARCHIVO + VERSION + salt + nonce + ciphertext


def decrypt_bytes(encrypted_data: bytes, password: str) -> bytes:
    if len(encrypted_data) < HEADER_SIZE:
        raise FileFormatError("El archivo cifrado es demasiado corto.")

    identificador = encrypted_data[: len(IDENTIFICADOR_ARCHIVO)]
    version = encrypted_data[
        len(IDENTIFICADOR_ARCHIVO) : len(IDENTIFICADOR_ARCHIVO) + len(VERSION)
    ]

    if identificador != IDENTIFICADOR_ARCHIVO:
        raise FileFormatError("El archivo no tiene el formato esperado.")
    if version != VERSION:
        raise FileFormatError("Version de archivo cifrado no soportada.")

    offset = len(IDENTIFICADOR_ARCHIVO) + len(VERSION)
    salt = encrypted_data[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = encrypted_data[offset : offset + NONCE_SIZE]
    ciphertext = encrypted_data[offset + NONCE_SIZE :]

    key = derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def encrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    plaintext = input_path.read_bytes()
    encrypted_data = encrypt_bytes(plaintext, password)
    output_path.write_bytes(encrypted_data)


def decrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    encrypted_data = input_path.read_bytes()
    plaintext = decrypt_bytes(encrypted_data, password)
    output_path.write_bytes(plaintext)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cifra y descifra archivos usando AES-256-GCM."
    )
    parser.add_argument(
        "action",
        choices=("encrypt", "decrypt"),
        help="Operacion a realizar: encrypt o decrypt.",
    )
    parser.add_argument("input_file", help="Archivo de entrada.")
    parser.add_argument("output_file", help="Archivo de salida.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    input_path = Path(args.input_file)
    output_path = Path(args.output_file)

    if not input_path.is_file():
        print(f"Error: no existe el archivo de entrada: {input_path}", file=sys.stderr)
        return 1
    if output_path.exists():
        print(f"Error: el archivo de salida ya existe: {output_path}", file=sys.stderr)
        return 1

    password = getpass.getpass("Contrasena: ")
    if not password:
        print("Error: la contrasena no puede estar vacia.", file=sys.stderr)
        return 1

    try:
        if args.action == "encrypt":
            encrypt_file(input_path, output_path, password)
        else:
            decrypt_file(input_path, output_path, password)
    except FileFormatError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except InvalidTag:
        print(
            "Error: no se pudo descifrar. La contrasena es incorrecta o el archivo fue modificado.",
            file=sys.stderr,
        )
        return 1

    print(f"Archivo generado: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
