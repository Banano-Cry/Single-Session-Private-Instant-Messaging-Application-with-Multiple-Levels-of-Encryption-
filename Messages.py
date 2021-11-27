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