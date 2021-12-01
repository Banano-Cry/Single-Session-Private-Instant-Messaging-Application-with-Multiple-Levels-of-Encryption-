import socket
import threading
import datetime
import os
import numpy as np
import time
import cryptography
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Encryption import KSA, PRGA, llave_to_array
from Hash import calcHashSHA3
#######################################################
#                   INITIALIZATION
#######################################################
FORMAT = 'utf-8'

PORT = 8080
SERVER = "127.0.0.1"
ADDR = (SERVER,PORT)
LlaveSim = None
privateKey = None
publicKey = None
clave_rc4 = None

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(ADDR)
server.listen()

client_list = []
nicknames = []

def encriptarLlavePriv(llavePriv,claveRC):
    try:
        llave = llave_to_array(claveRC)
        S = KSA(llave)
        cadena_cifrante = np.array(PRGA(S, len(llavePriv)))
        llavePriv = np.array([i for i in llavePriv])
        cipher = cadena_cifrante ^ llavePriv
        llavePrivCifrada = cipher.astype(np.uint8).data.hex()
        return llavePrivCifrada
    except Exception as e:
        print("Error in [EncriptarLlavePriv]:",e)

def generarParLlaves():
    try:
        key = RSA.generate(1024)
        privateKey = key.export_key()
        publicKey = key.publickey().export_key()
        return privateKey, publicKey
    except Exception as e:
        print("Error in [generarParLLaves]:",e)

def generarLlaveSimetrica():
    try:
        LlaveSimetrica = Fernet.generate_key()
        return LlaveSimetrica
    except Exception as e:
        print("Error in [GenerarLlaveSimetrica]:",e)

def broadcastLlaveSimetrica(LlaveSimetrica):
    try:
        broadcast(LlaveSimetrica)
    except Exception as e:
        print(e)

def encriptarLlaveSim(LlaveSim, LlavePublica):
    try:
        public_key = RSA.import_key(LlavePublica)
        public_crypter =  PKCS1_OAEP.new(public_key)
        key_encrypted = public_crypter.encrypt(LlaveSim)
        return key_encrypted
    except Exception as e:
        print("Error in [EncriptarLlaveSim]:",e)  

class serverThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self,name='Server')
        self.status = True

    def run(self):
        try:
            if os.name == "nt":
                os.system("cls")
            else:
                os.system('clear')
        except Exception as e:
            print("Error in [ServerThread][run]:",e)
            print("The program will continue")

        try:
            print("[STARTING] Server listening ...")
            print(chr(27)+'[1;33m'+"\t\t\t\t[INFO] para ver los comandos escribir 'help' [INFO]")
            print(chr(27)+'[0;37m',end="")
            while(self.status):
                if self.status:
                    consoleCommand = str(input(chr(27)+'[1;37m'+'\n[Server]$ '))
                    if consoleCommand == "":
                        pass
                    elif consoleCommand == "help":
                        print(chr(27)+'[1;33m',end="")
                        print("\n\t[*]Lista de comandos del servidor[*]")
                        print("\t[1]exit --> Salir del servidor")
                        print("\t[2]count --> Cantidad de usuarios en el servidor")
                        print("\t[3]list --> Lista a los usuarios en el servidor")
                        print("\t[4]key --> Muestra la clave RC4 temporal")

                    elif consoleCommand == "list":
                        print(chr(27)+'[1;33m',end="")
                        print(f"[*] Hay {len(client_list)} usuarios en el servidor [*]")

                    elif consoleCommand == "count":
                        print(chr(27)+'[1;33m',end="")
                        print("[*] Los usuarios conectados actualmente son: [*]")
                        for num, name in enumerate(nicknames):
                            print(f"[{num + 1}] {name}")

                    elif consoleCommand == "key":
                        print(chr(27)+'[1;33m',end="")
                        print(f"[*] La clave RC4 actual es '{clave_rc4}' [*]")

                    elif consoleCommand == "exit":
                        print(chr(27)+'[1;31m',end="")
                        print("[-] Apagando servidor")
                        serverThread.status = False
                        server.close()
                        os._exit(0)
                        
        except Exception as e:
            print("Error in [ServerThread] {Error with if structure}:",e)

def broadcast(msg):
    try:
        for client in client_list:
            client.send(msg)
    except Exception as e:
        print("Error in [brodcast]:",e)

def close(client):
    try:
        index = client_list.index(client)
        client_list.remove(client)
        nickname = nicknames[index]
        print(chr(27)+'[1;31m',end="")
        print(f"[-] Se ha desconectado {nickname}...")
        print(chr(27)+'[0;37m',end="")
        broadcast(f"{nickname} ha dejado el chat...".encode(FORMAT))
        nicknames.remove(nickname)
        client.close()
    except Exception as e:
        print("Error in [Close]:",e)

def handle_client(client):
    while True:
        try:
            message = client.recv(2048)
            if message == b"":
                close(client)
                break
            print(chr(27)+'[1;33m',end="")
            print(f"$ {nicknames[client_list.index(client)]}")
            message =  str.encode("enc*") + message
            broadcast(message)

        except Exception as e:
            print("Error in [handle_client]:",e)
            close(client)
            break

def createKeys():
    global privateKey
    global publicKey
    global LlaveSim
    try:
        privateKey, publicKey = generarParLlaves()
        privateKey = encriptarLlavePriv(privateKey, clave_rc4)
        LlaveSim = generarLlaveSimetrica()
        LlaveSim = encriptarLlaveSim(LlaveSim, publicKey)
    except Exception as e:
        print("Error in [CreateKeys]:",e)

def negotiationRC4(client, addr):
    attempt = 0
    try:
        while True:
            rc4 = client.recv(1024).decode(FORMAT)
            if attempt == 2:
                client.send("500".encode(FORMAT))
                client.close()
                print(chr(27)+'[1;31m',end="")
                print(f"[LOG:{datetime.datetime.now()}] Un usuario ha fallado muchas veces la clave RC4 [LOG]")
                print(chr(27)+'[0;37m',end="")
                return False
            elif rc4 == calcHashSHA3(clave_rc4):
                client.send("200".encode(FORMAT))
                return True
            else:
                client.send("400".encode(FORMAT))
                attempt+=1
        return False
    except Exception as e:
        print("Error in [NegotiationRC4]:",e)
        
def receive():
    createKeys()
    try:
        while True:
            try:
                client, addr = server.accept()
            except Exception as e:
                print("Error in [Receive]{Error accepting client}:",e)

            try:
                if negotiationRC4(client, addr):   
                    time.sleep(1)
                    print(f'Connected with {addr}')

                    try:
                        client.send("Nickname?: ".encode(FORMAT))
                        nickname = client.recv(1024)
                    except Exception as e:
                        print("Error in [Receive]{Error sending or receiving client Nickname}:",e)

                    try:
                        client.send("SYN".encode(FORMAT))
                        respuesta = client.recv(1024).decode(FORMAT)
                    except Exception as e:
                        print("Error in [Receive]{Error sending or receiving SYN message}:",e)

                    try:
                        if respuesta == "ACK":
                            try:
                                client.send(privateKey.encode(FORMAT))
                                recv = client.recv(1024).decode(FORMAT)
                            except Exception as e:
                                print("Error in [Receive]{Error sending or receiving RECV message}:",e)

                            if recv == "RECV":
                                try:
                                    client.send(LlaveSim)
                                    recv_2 = client.recv(1024).decode(FORMAT)
                                except Exception as e:
                                    print("Error in [Receive]{Error sending symmetric key or receiving RECV SIM message}")

                                if recv_2 == "RECV SIM":                        #SIM???
                                    print("[+] Envio exitoso doble")
                                    client_list.append(client)
                                    nicknames.append(nickname)
                            else:
                                print("[-] Envio fallido")

                        elif respuesta == "RC4":
                            pass

                    except Exception as e:
                        print("Error in [Receive]{Error with ACK message}:",e)

                    print(chr(27)+'[1;32m',end="")
                    print(f"[+] {nickname} ha entrado al chat!")
                    broadcast(f"{nickname} ha entrado al chat!\n".encode(FORMAT))

                    try:
                        client.send("Connected to the server.".encode(FORMAT))
                    except Exception as e:
                        print("Error in [Receive]{Error sending connection broadcast}:",e)

                    try:
                        thread = threading.Thread(target=handle_client, args=(client,))
                        thread.start()
                    except Exception as e:
                        print("Error in [Receive]{Error creating thread for client}:",e)

                else:
                    continue

            except Exception as e:
                print("Error in [Receive]{Error with if structure}:",e)

    except Exception as e:
        print("Error in [Receive]:",e)

def main():
    global serverThread
    try:
        serverThread = serverThread()
        serverThread.start()
        receive()
    except Exception as e:
        print("Error in [Main]:",e)

if __name__ == "__main__":
    clave_rc4 = input("[+]Escriba la clave RC4 de la sesion: ")
    main()
