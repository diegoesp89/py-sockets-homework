#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

HOST = "127.0.0.1"
PORT = 4444


#este es el string de la clave publica, en caso de no ser válida, generar una con el archivo crypto.py, quedará la clave en un archivo llamado id_rsa.pub
public_key = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuHloLRdI9gA9SZITSJeo
/v9DgRxtKWIYr/cWvTrI6KTsScLe49QVOEBZ7obkxb3Ea3c0kJx6otuUmTgV4IrQ
Yj1f7EDEq1WypAKqkxVidzudL7cQGcqZ5Z0Uf/BQTaY5x5I1LrePBxNkXiSxW7EA
JmK8GHHpgZjLkF6E5e9K9xQNRXu2AEekC3Us02dquIsvX/Z9wKOdkoo/4ZGzeeEq
eOwhjK1dJqwUhG1Wd50QtRTT/n8TB87aql3FwtpLCk2O5fK7RrxhOlLr9P67tB3L
EQ0SJxCrFpdi9xIl2cZbJB8H26YHq78xbG0xKhX6fZDv8HZVWLCbRz2djMfBmtp2
WQIDAQAB
-----END PUBLIC KEY-----'''

public_key = serialization.load_pem_public_key(
    public_key.encode(),
    backend=default_backend()
)

def encrypt_msg(msg):
    encrypted = public_key.encrypt(
    msg,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
    return encrypted


while True:
    data = input("Remote Console:")
    data = data.encode()
    encrypted = encrypt_msg(data)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect_ex((HOST, PORT))
        sock.sendall(encrypted)
        data = sock.recv(1024)
        print(data.decode())