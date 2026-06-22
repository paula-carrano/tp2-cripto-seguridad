# AES-256 File Tool

CLI en Python para cifrar y descifrar archivos usando AES-256-GCM.

## Instalacion

```bash
pip install -r requirements.txt
```

## Uso

El proyecto incluye una carpeta `ejemplos` con esta organizacion:

```text
ejemplos/
  para_encriptar/    archivos originales
  encriptados/       archivos cifrados .enc
  desencriptados/    archivos recuperados
```

Para cifrar el archivo de ejemplo:

```bash
python aes_file_tool.py encrypt ejemplos/para_encriptar/mensaje.txt ejemplos/encriptados/mensaje.txt.enc
```

Para descifrarlo:

```bash
python aes_file_tool.py decrypt ejemplos/encriptados/mensaje.txt.enc ejemplos/desencriptados/mensaje_recuperado.txt
```

El programa pide la contrasena por consola y no la muestra mientras se escribe.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```
