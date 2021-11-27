"""
This file contain all the Encryption functions used in the project
"""

def llave_to_array(llave):
    """
    Format key
    """
    return [ord(c) for c in llave]

def KSA(llave):
    """
    Generate KSA 
    """
    longitud_llave = len(llave)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + llave[i%longitud_llave]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def PRGA(S,n):
    """
    Generate PRGA
    """
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