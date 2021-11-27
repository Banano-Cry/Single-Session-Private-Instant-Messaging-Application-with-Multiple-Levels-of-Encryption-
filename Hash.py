"""
This file contain all the hash functions used in the project
"""
from Crypto.Hash import MD5, SHA512

def calcHashMD5(msg): 
    """
    Calc the hash MD5 of the message
    """
    msgHashed = MD5.new()
    msgHashed.update(msg.encode())
    return msgHashed.hexdigest()

def checkHashMD5(msg):
    """
    Check if the message was modified in the transmission 
    """
    hash = msg[-32:]
    msg = msg[:-32]
    if hash == calcHashMD5(msg):
        return (False, msg)
    else:
        return (True, msg)

def calcHashSHA3(msg):
    """
    Calc the hash SHA512 of the message
    """
    msgHashed = SHA512.new()
    msgHashed.update(msg.encode())
    return msgHashed.hexdigest()