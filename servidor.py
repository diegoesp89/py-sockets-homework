#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import datetime


HOST = "127.0.0.1"
PORT = 4444

#se abre el archivo con la clave privada
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

#funcion para encriptar el mensaje
def decrypt_msg(msg):
    decrypted = private_key.decrypt(
    msg,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    )
    return decrypted

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    print("Starting the server...")

    sock.bind((HOST, PORT))
    sock.listen()
    
    while True:
        connection, address = sock.accept()
        
        with connection:
            print(f"Connected by {address}")
            data = connection.recv(1024)
            #transform bytes to string
            data = decrypt_msg(data)
            data = data.decode()
            if data != "":
                
                result = os.popen(data).read()
                #saving the data to a file commands.txt with the date and time
                file = open("commands.txt", "a")
                ip = address[0]
                port = address[1]
                date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                file.write(f"{date} {ip}:{port} {data}\n")

                if(result == ""):
                    result = "No streaming data, but the command was executed"
                #send the result of the command to the client
                connection.send(result.encode())

            elif not data:
                connection.close()
                break
