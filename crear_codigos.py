#!/usr/bin/env python3
"""Genera un codigo de acceso por integrante y guarda SOLO los hashes en SSM.

Los codigos en texto plano se muestran una unica vez en la terminal.
No se escriben en ningun archivo.
Volver a ejecutar el script rota los codigos de todos.
"""
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile

PARAM = "/juice-portal/codes"
REGION = "us-east-1"
# Reemplazar por los nombres reales del equipo (los mismos que se escriben en el portal)
NOMBRES = ["Nombre 1", "Nombre 2", "Nombre 3", "Nombre 4", "Nombre 5", "Nombre 6", "Nombre 7", "Nombre 8", "Nombre 9"]
# Sin caracteres ambiguos (0/O, 1/l/I) para que se puedan tipear desde el celular
ALFABETO = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
LARGO = 20  # 20 caracteres de un alfabeto de 57 = unos 117 bits de entropia
N, R, P = 2**14, 8, 1


def nuevo_codigo():
    return "".join(secrets.choice(ALFABETO) for _ in range(LARGO))


def hashear(codigo):
    sal = os.urandom(16)
    h = hashlib.scrypt(codigo.encode(), salt=sal, n=N, r=R, p=P, dklen=32)
    b64 = lambda x: base64.b64encode(x).decode()
    return f"scrypt${N}${R}${P}${b64(sal)}${b64(h)}"


def con_guiones(codigo):
    return "-".join(codigo[i:i + 5] for i in range(0, len(codigo), 5))


def main():
    codigos = {n: nuevo_codigo() for n in NOMBRES}
    hashes = {n: hashear(c) for n, c in codigos.items()}

    if os.environ.get("DRY_RUN"):
        print("DRY_RUN: no se guarda nada en SSM")
    else:
        fd, ruta = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(hashes, f)
            r = subprocess.run(
                ["aws", "ssm", "put-parameter",
                 "--name", PARAM, "--type", "SecureString",
                 "--value", f"file://{ruta}", "--overwrite",
                 "--region", REGION],
                capture_output=True, text=True)
        finally:
            os.remove(ruta)
        if r.returncode != 0:
            print("ERROR al guardar en SSM. No se muestran codigos.")
            print(r.stderr)
            sys.exit(1)
        print(f"Hashes guardados en SSM ({PARAM}).")

    print("\nCODIGOS (se muestran una sola vez, copialos y pasalos por privado):\n")
    for n in NOMBRES:
        print(f"  {n:<10} {con_guiones(codigos[n])}")
    print("\nCuando los hayas copiado, ejecuta: clear")


if __name__ == "__main__":
    main()
