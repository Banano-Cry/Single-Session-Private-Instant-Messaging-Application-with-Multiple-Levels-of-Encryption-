import socket
import threading
import time
import sys
import os
import numpy as np
import cryptography
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Encryption import llave_to_array
from Hash import calcHashMD5, calcHashSHA3, checkHashMD5
from Messages import commands, disclaimer, integridadComprometida
from server import PRGA, KSA

try:
    PORT = 19188
    FORMAT = 'utf-8'
    SERVER = "6.tcp.ngrok.io"
    ADDR = (SERVER,PORT)
    LlavePrivada = None
    LlaveSim = None
    nickname = ""
    clave_rc4 = None #Clave de prueba
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

except ValueError as e:
    print(e)
    input()

def write():
    while True:
        msg = input("> ")
        #print("Mi mensaje: ")
        #print(msg)
        #print("Mi mensaje encriptado:")
        #print(encriptarMsg(msg,LlaveSim))
        if(len(msg) == 0):
            continue

        elif(msg[0] == "/"):
            commands(msg,client)

        else:
            msg = msg + calcHashMD5(msg)
            msg = encriptarMsg(msg,LlaveSim)
            data = f"$ {nickname}: {msg}"
            client.send(data.encode(FORMAT))

def receive():
    global LlavePrivada
    global LlaveSim
    while True:
        try:
            msg = client.recv(2048).decode(FORMAT)

            if msg == "Nickname?: ":
                client.send(nickname.encode(FORMAT))
                
            elif msg == "SYN":
                client.send("ACK".encode(FORMAT))
                try:
                    LlavePrivada = client.recv(2048)
                    client.send("RECV".encode(FORMAT))
                    LlaveSim = client.recv(2048)
                    if LlaveSim is not None:
                        client.send("RECV SIM".encode(FORMAT))
                        #print(LlaveSim)
                    #print(LlavePrivada)
                    LlavePrivada = desencriptarLlavePriv(LlavePrivada,clave_rc4)
                    LlaveSim = desencriptarLlaveSimetrica(LlaveSim,LlavePrivada)
                    #print(LlaveSim)
                except:
                    print("Error en el intercambio")

            elif msg.split("*",1)[0] == "enc":
                #print("Intento de mensaje desencriptado")
                #print(LlaveSim)
                nick, msg = desencriptarMsg(msg,LlaveSim)
                if nick.split(" ")[1] == nickname:
                    print(chr(27) + '[1;33m',end="")
                else:
                    print(chr(27) + '[1;35m',end="")
                print(f"{nick}: {msg}")
                print(chr(27)+'[0;37m',end="")

            else:
                
                #print(chr(27)+'[0;37m',end="")
                if(len(msg) == 0):
                    print(chr(27)+'[1;31m',end="")
                    print("[-] Servidor desconectado")
                    client.close()
                    os._exit(0)
                else:
                    print(chr(27)+'[0;37m',end="")
                    print(msg)

        except Exception as e:
            print(e)
            client.close()
            os._exit(0)

def desencriptarLlavePriv(LlavePriv, ClaveRC):
  
    llave = llave_to_array(ClaveRC)

    S = KSA(llave)
    cadena_cifrante = np.array(PRGA(S, len(LlavePriv)//2))
    #print("\nKeystream:")
    #print(cadena_cifrante)

    hex_list = [LlavePriv[i:i+2] for i in range(0, len(LlavePriv), 2)]
    texto2 = np.array([int(i,16) for i in hex_list])

    NuevaLlavePriv = cadena_cifrante ^ texto2

    #print("\nLlave privada en Hexadecimal:")
    #print(LlavePriv) #imprime en hexadecimal
    #print("\nUnicode:")
    NuevaLlavePriv = "".join([chr(c) for c in NuevaLlavePriv])
    #print("nueva llave priv desencriptada")
    #print(NuevaLlavePriv)
    return NuevaLlavePriv

def desencriptarLlaveSimetrica(LlaveSimetricaEnc, LlavePrivada):
    try:
        # Private RSA key
        private_key = RSA.import_key(LlavePrivada)
        # Private decrypter
        private_crypter = PKCS1_OAEP.new(private_key)
        # Decrypted session key
        LlaveSimetricaDes = private_crypter.decrypt(LlaveSimetricaEnc)
        print('Llave simetrica desencriptada exitosamente!')
        return LlaveSimetricaDes
    except ValueError as e:
        print("Error Tecnico: " + str(e))

def encriptarMsg(msg, LlaveSimetrica): #solo prueba

    #msgHash = calcHash(msg)
    #newMsg = msg + msgHash 
    fernet = Fernet(LlaveSimetrica)
    newMsg = str.encode(msg)
    encrypted = fernet.encrypt(newMsg)
    #print("Mensaje encriptado: " + str(encrypted))
    return encrypted

def desencriptarMsg(msg, LlaveSimetrica): #solo prueba
    #print(msg)
    newMsg = msg.split("*",1)
    msg2 = newMsg[1].split(": ",1)
    nick = msg2[0]
    msg3 = msg2[1]
    msg4 = msg3.split("'",2) 
    #print("mensaje spliteado")
    #print(msg4)
    try:
        fernet = Fernet(LlaveSimetrica)
        decrypted = fernet.decrypt(str.encode(msg4[1])).decode()
        verify, msg = checkHashMD5(decrypted)
        if verify:
            integridadComprometida(client)
            print(chr(27)+'[0;37m',end="")

        return nick, msg
        #newMsg = "".join(i for i in newMsg)
    except Exception as e:
        print(e) 

def sendRC4():
    global clave_rc4
    while True:
        print(chr(27)+'[0;37m',end="")
        clave_rc4 = input("Ingrese la clave acordada entre los clientes: ")
        client.send(calcHashSHA3(clave_rc4).encode(FORMAT))
        codeNumber = int(client.recv(50).decode(FORMAT))
        if codeNumber == 200:
            return True
        elif codeNumber == 400:
            print(chr(27)+'[1;33m',end="")
            print("[-] Clave incorrecta")
            continue
        elif codeNumber == 500:
            print(chr(27)+'[1;31m',end="")
            print("[-] El servidor te desconecto")
            client.close()
            os._exit(0)
        
def startClient():
    client.connect(ADDR)
    return sendRC4()

def main():
    disclaimer()
    thread_recieve = threading.Thread(target=receive)
    thread_write = threading.Thread(target=write)

    thread_recieve.start()
    thread_write.start()

if __name__ == "__main__":
    nickname = input("Ingrese su nombre de usuario: ")
    if startClient():
        main()
