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
from Crypto.Hash import SHA512
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

def calcHashSHA3(msg):
    msgHashed = SHA512.new()
    msgHashed.update(msg.encode())
    return msgHashed.hexdigest()
def KSA(llave):
    longitud_llave = len(llave)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + llave[i%longitud_llave]) % 256
        S[i], S[j] = S[j], S[i]
    return S
def PRGA(S,n):
    i = 0
    j = 0
    llave = []

    while n>0:
        n = n - 1
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[ (S[i] + S[j]) % 256 ]
        llave.append(K)
    return llave

def llave_to_array(llave):
    return [ord(c) for c in llave]

def encriptarLlavePriv(llavePriv,claveRC):
    
    llave = llave_to_array(claveRC)
    S = KSA(llave)
    cadena_cifrante = np.array(PRGA(S, len(llavePriv)))
    #print("\nKeystream:")
    #print(cadena_cifrante)
    #llavePriv = np.array([chr(i) for i in llavePriv])
    llavePriv = np.array([i for i in llavePriv])

    cipher = cadena_cifrante ^ llavePriv #XOR dos arrays
    #print(cipher)

    #print("\nCipher en Hexadecimal:")
    #print(cipher.astype(np.uint8).data.hex()) #imprime en hexadecimal
    llavePrivCifrada = cipher.astype(np.uint8).data.hex()
    return llavePrivCifrada

#Generacion de llaves
def generarParLlaves():
    try:
        # Generates RSA Encryption + Decryption keys / Public + Private keys
        key = RSA.generate(1024)

        privateKey = key.export_key()
        publicKey = key.publickey().export_key()

        return privateKey, publicKey
    except Exception as e:
        print(e)
def generarLlaveSimetrica():
    LlaveSimetrica = Fernet.generate_key()
    return LlaveSimetrica
def broadcastLlaveSimetrica(LlaveSimetrica):
    try:
        broadcast(LlaveSimetrica)
    except Exception as e:
        print(e)

def encriptarLlaveSim(LlaveSim, LlavePublica):
    try:
            # Public encrypter object
            public_key = RSA.import_key(LlavePublica)
            public_crypter =  PKCS1_OAEP.new(public_key)
            # Encrypted fernet key
            key_encrypted = public_crypter.encrypt(LlaveSim)
            # Write encrypted fernet key to file
            #print("Llave simetrica encriptada exitosamente.")

            return key_encrypted
    except Exception as e:
        print("Error técnico." + str(e))   

class serverThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self,name='Server')
        self.status = True

    def run(self):
        if os.name == "nt":
            os.system("cls")
        else:
            os.system('clear')
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

#Broadcast
def broadcast(msg):
    for client in client_list:
        client.send(msg)

def close(client):
    index = client_list.index(client)
    client_list.remove(client)
    nickname = nicknames[index]
    print(chr(27)+'[1;31m',end="")
    print(f"[-] Se ha desconectado {nickname}...")
    print(chr(27)+'[0;37m',end="")
    broadcast(f"{nickname} ha dejado el chat...".encode(FORMAT))
    nicknames.remove(nickname)
    client.close()

#handle
def handle_client(client): #manejador de la conexion con el cliente
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

        except:
            close(client)
            break

def createKeys():
    global privateKey
    global publicKey
    global LlaveSim
    privateKey, publicKey = generarParLlaves()
    privateKey = encriptarLlavePriv(privateKey, clave_rc4)
    #print(privateKey)
    LlaveSim = generarLlaveSimetrica()
    #print("llave simetrica")
    #print(LlaveSim)
    LlaveSim = encriptarLlaveSim(LlaveSim, publicKey)
    #print("Nueva Llave simetrica")
    #print(LlaveSim)

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
        print(e)
        
#receive
def receive():
    createKeys()
    while True:
        client, addr = server.accept()
        if negotiationRC4(client, addr):   
            time.sleep(1)
            print(f'Connected with {addr}')

            client.send("Nickname?: ".encode(FORMAT))
            nickname = client.recv(1024)

            client.send("SYN".encode(FORMAT))
            respuesta = client.recv(1024).decode(FORMAT)

            #print("esta es la resp: " + str(respuesta))
            if respuesta == "ACK":
                    client.send(privateKey.encode(FORMAT)) #ojo con el encode pq ya esta en hex
                    recv = client.recv(1024).decode(FORMAT)
                    if recv == "RECV":
                        client.send(LlaveSim)
                        recv_2 = client.recv(1024).decode(FORMAT)
                        if recv_2 == "RECV SIM":                        
                            print("Envio exitoso doble")
                            client_list.append(client)
                            nicknames.append(nickname)
                    else:
                        print("Envio fallido")

            elif respuesta == "RC4":
                pass

            print(chr(27)+'[1;32m',end="")
            print(f"[+] {nickname} ha entrado al chat!")
            broadcast(f"{nickname} ha entrado al chat!\n".encode(FORMAT))
            client.send("Connected to the server.".encode(FORMAT))

            thread = threading.Thread(target=handle_client, args=(client,))
            thread.start()
        else:
            continue
def main():
    global serverThread
    serverThread = serverThread()
    serverThread.start()
    receive()

if __name__ == "__main__":
    clave_rc4 = input("[+]Escriba la clave RC4 de la sesion: ")
    main()
