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
from Crypto.Hash import MD5, SHA512

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

def calcHashSHA3(msg):
    msgHashed = SHA512.new()
    msgHashed.update(msg.encode())
    return msgHashed.hexdigest()
def commands(command):
    if(command[1:] == "help"):
        print(chr(27)+'[1;33m',end="")
        print("\n\t[*]Lista de comandos[*]")
        print("\t[1]/exit --> Salir del servidor")

    elif(command[1:] == "exit"):
        print("Cerrando conexion...")
        client.close()
        os._exit(0)
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
            commands(msg)

        else:
            msg = msg + calcHashMD5(msg)
            msg = encriptarMsg(msg,LlaveSim) #jejejeje
            data = f"$ {nickname}: {msg}"
            client.send(data.encode(FORMAT))
def disclaimer():
    print(chr(27) + '[1;31m',end="")
    print("\t\t\t\t***********************************************")
    print("\t\t\t\t*                  DISCLAIMER                 *")
    print("\t\t\t\t***********************************************")
    print(chr(27) + '[1;37m',end="")
    print("\t\tPara facilidad en la visualizacion, los mensajes que envie el usuario se pondran de color amarillo:")
    print(chr(27) + '[1;33m'+'\t\tEjemplo')
    print(chr(27) + '[1;37m'+'\t\tLos mensajes que reciba de otro cliente se pondran en morado:')
    print(chr(27) + '[1;35m'+'\t\tEjemplo')
    print(chr(27) + '[1;37m',end="\n")
    print(chr(27)+'[1;33m'+"\t\t\t\t[INFO] para ver los comandos escribir '/help' [INFO]")
    print(chr(27)+'[0;37m',end="")
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
            break
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
def calcHashMD5(msg): 
    msgHashed = MD5.new()
    msgHashed.update(msg.encode())
    return msgHashed.hexdigest()
def encriptarMsg(msg, LlaveSimetrica): #solo prueba

    #msgHash = calcHash(msg)
    #newMsg = msg + msgHash 
    fernet = Fernet(LlaveSimetrica)
    newMsg = str.encode(msg)
    encrypted = fernet.encrypt(newMsg)
    #print("Mensaje encriptado: " + str(encrypted))
    return encrypted

def checkHashMD5(msg):
    hash = msg[-32:]
    msg = msg[:-32]
    if hash == calcHashMD5(msg):
        return (False, msg)
    else:
        return (True, msg)

def integridadComprometida():
    print(chr(27)+'[1;33m',end="")
    print("\t\t\t\t***********************************************")
    print("\t\t\t\t*           INTEGRIDAD COMPROMETIDA           *")
    print("\t\t\t\t***********************************************")
    print("[*] El servidor ha sido informado del problema, desesa salir? [Y] [N]")
    res = input("[*] ")
    if res.lower() == "n":
        return True
    elif res.lower() == "y":
        print("[-] El programa se cerrara...")
        client.close()
        os._exit(0)
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
            print(chr(27)+'[1;31m',end="")
            print("[-] INTEGRIDAD COMPROMETIDA, EL MENSAJE NO CORRESPONDE CON EL HASH")
            integridadComprometida()
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
