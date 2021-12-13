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
import PySimpleGUI as sg

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

sg.theme('DarkAmber')

layout_chat_box = [[sg.Text('Chat', size=(40, 1))],
          [sg.Output(size=(110, 20), font=('Helvetica 10'))],
          [sg.Multiline(size=(70, 5), enter_submits=True, key='-QUERY-', do_not_clear=False),
           sg.Button('SEND', button_color=(sg.YELLOWS[0], sg.BLUES[0]), bind_return_key=True),
           sg.Button('EXIT', button_color=(sg.YELLOWS[0], sg.GREENS[0]))]]

window_chat_box = sg.Window('Chat window', layout_chat_box, font=('Helvetica', ' 13'), default_button_element_size=(8,2), use_default_focus=False)

def askName():
    layout_start_menu = [[sg.Text('Write your username:')],
                        [sg.InputText(key='-NAME-')],
                        [sg.Submit(), sg.Button('Exit')]]

    window_start_menu = sg.Window('SignIn', layout_start_menu)
    event, values = window_start_menu.read()
    if event == sg.WIN_CLOSED or event == 'Exit':
        window_start_menu.close()
        os._exit(0)
    name=values['-NAME-']
    window_start_menu.close()
    return name

def write():
    while True:
        event, value = window_chat_box.read()
        if event in (sg.WIN_CLOSED, 'EXIT'):
            break
        if event == 'SEND':
            query = value['-QUERY-'].rstrip()

            if(len(query) == 0):
                continue

            elif(query[0] == "/"):
                    commands(query,client)

            else:
                try:
                    query = query + calcHashMD5(query)
                    query = encriptarMsg(query,LlaveSim)
                    data = f"[{nickname}]: {query}"
                    client.send(data.encode(FORMAT))

                except Exception as e:
                    print("Error in [write] {Error with client sending message}:",e)
    window_chat_box.close()
    os._exit(0)

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
                        print(f"{nick}: {msg}")
                    except Exception as e:
                        print("Error in [Receive] {Error with decrypting message}:",e)

                else:
                    if(len(msg) == 0):
                        print("[-] Servidor desconectado")
                        client.close()
                        os._exit(0)
                    else:
                        print(msg)

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
        #print('Llave simetrica desencriptada exitosamente!')
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
    layout_password = [[sg.Text('Type the password:')],
          [sg.Input(key='-PASSWORD-')],
          [sg.Button('Submit',bind_return_key=True),
            sg.Button('Exit')]]

    window_password = sg.Window('Request Password', layout_password)
    while True:
        try:
            event, values = window_password.read()
            if event == sg.WIN_CLOSED or event == 'Exit':
                break
            if event == 'Submit':
                clave_rc4 = values['-PASSWORD-']
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
                    window_password.close()
                    return True
                elif codeNumber == 400:
                    sg.popup("You have entered an incorrect password")
                    continue
                elif codeNumber == 500:
                    sg.popup("The server has disconnected you")
                    window_password.close()
                    client.close()
                    os._exit(0)
            except Exception as e:
                print("Error in [SendRC4] {codeNumber Validation}:",e)

        except Exception as e:
            print("Error in [SendRC4]:",e)
    window_password.close()
    return False

def startClient():
    try:
        client.connect(ADDR)
        return sendRC4()
    except Exception as e: 
        print("Error in [StartClient]:",e)

def main():

    '''try:
        thread_write = threading.Thread(target=write)
    except Exception as e:
        print("Error in [Main] {Error with write thread}:",e)'''

    try:
        thread_recieve = threading.Thread(target=receive)
    except Exception as e:
        print("Error in [Main] {Error with reciever thread}:",e)

    try:
        #thread_write.start()
        thread_recieve.start()
        write()
    except Exception as e:
        print("Error in [Main] {Error with starting threads}:",e)

if __name__ == "__main__":
    nickname = askName()
    if startClient():
        try:
            main()
        except Exception as e:
            print("Error in [Main]:",e)
