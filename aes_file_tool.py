import argparse
import getpass
import sys
from pathlib import Path

# Imports de la libreria cryptography usados para AES-GCM y PBKDF2.
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os


# Constantes del formato propio del archivo cifrado.
# MAGIC y VERSION permiten reconocer que el archivo fue generado por este programa.
MAGIC = b"AES256GCM"
VERSION = b"\x01"

# Tamanos recomendados para AES-GCM y PBKDF2.
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 390_000

# Cantidad minima de bytes que debe tener un archivo cifrado valido.
HEADER_SIZE = len(MAGIC) + len(VERSION) + SALT_SIZE + NONCE_SIZE


class FileFormatError(ValueError):
    # Error propio para indicar que el archivo no tiene el formato esperado.
    pass


def derive_key(password: str, salt: bytes) -> bytes:
    # Convierte la contrasena del usuario en bytes para poder usarla en PBKDF2.
    password_bytes = password.encode("utf-8")

    # PBKDF2-HMAC-SHA256 deriva una clave de 256 bits desde la contrasena.
    # El salt hace que la clave derivada sea distinta en cada cifrado.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password_bytes)


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    # Se generan valores aleatorios nuevos para cada cifrado.
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    # A partir de la contrasena y el salt se obtiene la clave AES-256.
    key = derive_key(password, salt)

    # AES-GCM cifra el contenido y agrega una etiqueta de autenticacion.
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    # El archivo cifrado guarda encabezado + salt + nonce + contenido cifrado.
    # El salt y el nonce no son secretos; se necesitan para descifrar.
    return MAGIC + VERSION + salt + nonce + ciphertext


def decrypt_bytes(encrypted_data: bytes, password: str) -> bytes:
    # Primero se verifica que el archivo tenga al menos el encabezado minimo.
    if len(encrypted_data) < HEADER_SIZE:
        raise FileFormatError("El archivo cifrado es demasiado corto.")

    # Se leen los identificadores iniciales del formato.
    magic = encrypted_data[: len(MAGIC)]
    version = encrypted_data[len(MAGIC) : len(MAGIC) + len(VERSION)]

    # Si estos valores no coinciden, el archivo no fue generado por esta herramienta.
    if magic != MAGIC:
        raise FileFormatError("El archivo no tiene el formato esperado.")
    if version != VERSION:
        raise FileFormatError("Version de archivo cifrado no soportada.")

    # Se separan el salt, el nonce y el contenido cifrado.
    offset = len(MAGIC) + len(VERSION)
    salt = encrypted_data[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = encrypted_data[offset : offset + NONCE_SIZE]
    ciphertext = encrypted_data[offset + NONCE_SIZE :]

    # Se vuelve a derivar la misma clave y se intenta descifrar.
    # Si la contrasena es incorrecta o el archivo fue modificado, AESGCM falla.
    key = derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def encrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    # Lee el archivo completo, cifra sus bytes y escribe el resultado.
    plaintext = input_path.read_bytes()
    encrypted_data = encrypt_bytes(plaintext, password)
    output_path.write_bytes(encrypted_data)


def decrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    # Lee el archivo cifrado, recupera el contenido original y lo escribe.
    encrypted_data = input_path.read_bytes()
    plaintext = decrypt_bytes(encrypted_data, password)
    output_path.write_bytes(plaintext)


def build_parser() -> argparse.ArgumentParser:
    # Define los argumentos que se reciben por consola.
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
    # Lee los argumentos ingresados por el usuario.
    parser = build_parser()
    args = parser.parse_args()

    input_path = Path(args.input_file)
    output_path = Path(args.output_file)

    # Validaciones simples para evitar errores comunes.
    if not input_path.is_file():
        print(f"Error: no existe el archivo de entrada: {input_path}", file=sys.stderr)
        return 1
    if output_path.exists():
        print(f"Error: el archivo de salida ya existe: {output_path}", file=sys.stderr)
        return 1

    # Pide la contrasena sin mostrarla en pantalla.
    password = getpass.getpass("Contrasena: ")
    if not password:
        print("Error: la contrasena no puede estar vacia.", file=sys.stderr)
        return 1

    # Ejecuta la accion solicitada y muestra errores entendibles.
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
    # Punto de entrada cuando el archivo se ejecuta desde la consola.
    raise SystemExit(main())
