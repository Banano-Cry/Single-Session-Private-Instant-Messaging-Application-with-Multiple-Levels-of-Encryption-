"""
This file contain all the messages that the program output if an action happend
"""

import os

def disclaimer():
    """
    Message from the beginning of the program
    """
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

def integridadComprometida(client):
    """
    If a MD5 hash of the message is not equal
    """
    print(chr(27)+'[1;31m',end="")
    print("[-] INTEGRIDAD COMPROMETIDA, EL MENSAJE NO CORRESPONDE CON EL HASH")
    print(chr(27)+'[1;33m',end="")
    print("\t\t\t\t***********************************************")
    print("\t\t\t\t*           INTEGRIDAD COMPROMETIDA           *")
    print("\t\t\t\t***********************************************")
    print("[*] El servidor ha sido informado del problema, desesa salir? [Y] [N]")
    print(chr(27)+'[0;37m',end="")
    res = input("[*] ")
    if res.lower() == "n":
        return True
    elif res.lower() == "y":
        print("[-] El programa se cerrara...")
        client.close()
        os._exit(0)

def commands(command,client):
    """
    Command chosen for the client
    """
    if(command[1:] == "help"):
        print(chr(27)+'[1;33m',end="")
        print("\n\t[*]Lista de comandos[*]")
        print("\t[1]/exit --> Salir del servidor")

    elif(command[1:] == "exit"):
        print("Cerrando conexion...")
        client.close()
        os._exit(0)

def serverCommands():
    print(chr(27)+'[1;33m',end="")
    print("\n\t[*]Lista de comandos del servidor[*]")
    print("\t[1]exit --> Salir del servidor")
    print("\t[2]count --> Cantidad de usuarios en el servidor")
    print("\t[3]list --> Lista a los usuarios en el servidor")
    print("\t[4]key --> Muestra la clave RC4 temporal")
    print(chr(27)+'[1;37m',end="")

def changeColor(message, color):
    color_select = {
        'black':'30',
        'red':'31',
        'green':'32',
        'yellow':'33',
        'blue':'34',
        'purple':'35',
        'cyan':'36',
        'white':'37',
    }
    print(chr(27)+f'[1;{color_select[color]}m',end='')
    print(message)
    print(chr(27)+'[1;37m',end="")
