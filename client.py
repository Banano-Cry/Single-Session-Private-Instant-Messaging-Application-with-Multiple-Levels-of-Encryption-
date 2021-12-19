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
from Messages import changeColor, commands, disclaimer, integridadComprometida
from server import PRGA, KSA

try:
    PORT = 8080
    FORMAT = 'utf-8'
    SERVER = "127.0.0.1"
    ADDR = (SERVER,PORT)
    LlavePrivada = None
    LlaveSim = None
    nickname = ""
    clave_rc4 = None
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

except ValueError as e:
    print(e)
    os._exit(0)

def write():
    while True:
        msg = input("> ")
        if(len(msg) == 0):
            continue

        elif(msg[0] == "/"):
                commands(msg,client)

        else:
            try:
                msg = msg + calcHashMD5(msg)
                msg = encriptarMsg(msg,LlaveSim)
                data = f"[{nickname}]: {msg}"
                client.send(data.encode(FORMAT))

            except Exception as e:
                print("Error in [write] {Error with client sending message}:",e)

def receive():
    global LlavePrivada
    global LlaveSim
    while True:
        try:
            try:
                msg = client.recv(2048).decode(FORMAT)
            except Exception as e:
                print("Error in [Receive] {Error getting message server}:",e)

            try:
                if msg == "Nickname?: ":
                    try:
                        client.send(nickname.encode(FORMAT))
                    except Exception as e:
                        print("Error in [Receive] {Error with sending message to server}:",e)
                    
                elif msg == "SYN":
                    client.send("ACK".encode(FORMAT))
                    try:
                        LlavePrivada = client.recv(2048)
                        client.send("RECV".encode(FORMAT))
                        LlaveSim = client.recv(2048)
                        if LlaveSim is not None:
                            client.send("RECV SIM".encode(FORMAT))
                        LlavePrivada = desencriptarLlavePriv(LlavePrivada,clave_rc4)
                        LlaveSim = desencriptarLlaveSimetrica(LlaveSim,LlavePrivada)
                    except:
                        print("Error in [Receive] {Error with SYN message}:",e)

                elif msg.split("*",1)[0] == "enc":
                    try:
                        nick, msg = desencriptarMsg(msg,LlaveSim)
                        if nick.strip('[]') == nickname:
                            changeColor(f"{nick}: {msg}",'yellow')
                        else:
                            changeColor(f"{nick}: {msg}",'purple')
                    except Exception as e:
                        print("Error in [Receive] {Error with decrypting message}:",e)

                else:
                    if(len(msg) == 0):
                        changeColor("[-] Servidor desconectado",'red')
                        client.close()
                        os._exit(0)
                    else:
                        changeColor(msg,'white')

            except Exception as e:
                print("Error in [Receive] {Error in if structure}:",e)

        except Exception as e:
            print("Error in [receive]:",e)
            client.close()
            os._exit(0)

def desencriptarLlavePriv(LlavePriv, ClaveRC):
    try:
        llave = llave_to_array(ClaveRC)
        S = KSA(llave)
        cadena_cifrante = np.array(PRGA(S, len(LlavePriv)//2))

        hex_list = [LlavePriv[i:i+2] for i in range(0, len(LlavePriv), 2)]
        texto2 = np.array([int(i,16) for i in hex_list])

        NuevaLlavePriv = cadena_cifrante ^ texto2
        NuevaLlavePriv = "".join([chr(c) for c in NuevaLlavePriv])
        return NuevaLlavePriv
    except Exception as e:
        print("Error in [DesencriptarLlavePriv]:",e)

def desencriptarLlaveSimetrica(LlaveSimetricaEnc, LlavePrivada):
    try:
        private_key = RSA.import_key(LlavePrivada)
        private_crypter = PKCS1_OAEP.new(private_key)
        LlaveSimetricaDes = private_crypter.decrypt(LlaveSimetricaEnc)
        print('Llave simetrica desencriptada exitosamente!')
        return LlaveSimetricaDes
    except Exception as e:
        print("Error in [DesencriptarLlaveSimetrica]:",e)

def encriptarMsg(msg, LlaveSimetrica):
    try:
        fernet = Fernet(LlaveSimetrica)
        newMsg = str.encode(msg)
        encrypted = fernet.encrypt(newMsg)
        return encrypted
    except Exception as e:
        print("Error in [EncriptarMsg]:",e)

def desencriptarMsg(msg, LlaveSimetrica):
    newMsg = msg.split("*",1)
    msg2 = newMsg[1].split(": ",1)
    nick = msg2[0]
    msg3 = msg2[1]
    msg4 = msg3.split("'",2) 
    try:
        fernet = Fernet(LlaveSimetrica)
        decrypted = fernet.decrypt(str.encode(msg4[1])).decode()
        verify, msg = checkHashMD5(decrypted)
        if verify:
            integridadComprometida(client)
        return nick, msg

    except Exception as e:
        print("Error in [DesencriptarMsg]:",e) 

def sendRC4():
    global clave_rc4
    codeNumber = -1
    while True:
        try:
            print(chr(27)+'[0;37m',end="")
            clave_rc4 = input("Ingrese la clave acordada entre los clientes: ")
            try:
                client.send(calcHashSHA3(clave_rc4).encode(FORMAT))
            except Exception as e:
                print("Error in [SendRC4] {client.send(calcHashSHA3(clave_rc4).encode(FORMAT))}:",e)
    
            try:
                codeNumber = int(client.recv(50).decode(FORMAT))
            except Exception as e:
                print("Error in [SendRC4] {codeNumber = int(client.recv(50).decode(FORMAT))}:",e)

            try:
                if codeNumber == 200:
                    return True
                elif codeNumber == 400:
                    changeColor("[-] Clave incorrecta",'yellow')
                    continue
                elif codeNumber == 500:
                    changeColor("[-] El servidor te desconecto",'red')
                    client.close()
                    os._exit(0)
            except Exception as e:
                print("Error in [SendRC4] {codeNumber Validation}:",e)

        except Exception as e:
            print("Error in [SendRC4]:",e)
        
def startClient():
    try:
        client.connect(ADDR)
        return sendRC4()
    except Exception as e: 
        print("Error in [StartClient]:",e)

def main():
    try:
        disclaimer()
    except Exception as e:
        print("Error in [Main] {Error With Show Disclaimer}:",e)

    try:
        thread_recieve = threading.Thread(target=receive)
    except Exception as e:
        print("Error in [Main] {Error with reciever thread}:",e)

    try:
        thread_write = threading.Thread(target=write)
    except Exception as e:
        print("Error in [Main] {Error with write thread}:",e)

    try:
        thread_recieve.start()
        thread_write.start()
    except Exception as e:
        print("Error in [Main] {Error with starting threads}:",e)

if __name__ == "__main__":
    nickname = input("Ingrese su nombre de usuario: ")
    if startClient():
        try:
            main()
        except Exception as e:
            print("Error in [Main]:",e)
