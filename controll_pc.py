import socket       
import hmac
import hashlib
from random import randrange
import math

controll_pc = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
host = socket.gethostname()                           
port = 9000        
hmac_pc_port = 8000
controll_pc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)                             
controll_pc.bind((host, port))                                  
controll_pc.listen(10)   

msg_counter = 0
q = 2971
g = 3


def BBS(seed):
    key_length = 254        
    q = 32452843
    p = 15485863
    M = q*p 
    key = ''
    for i in range(0, key_length):  #BBS formumla realization
        seed = (seed**2)%M
        bit = seed & 1              #Bit selection method; keeping only the LSB
        key += str(bit)
    key = hex(int(key, 2))          #Transforming the binary key to hex-dec
    return key


Z = True
while Z:
    clientsocket,addr = controll_pc.accept()
    msg = clientsocket.recv(1024)
    
    # Diffie-Hellman secure key exchange. Initiated by HMAC_pc
    if addr[1] == 8052 and msg.decode("utf-8").__contains__("key"):     # keyword "key" is used to identify the DH key exchange
        DH = msg.decode("utf-8").split(' ')                             # DH[1] = hmac pc public key
        private_key = randrange(10000)                                  # Controll_PC private key
        public_key_controll = (g ** private_key) % q                    # Controll_PC public key
        print("public key = ", public_key_controll)

        send_key = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        send_key.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        send_key.bind((host, 9050))
        send_key.connect((host, hmac_pc_port))
        send_key.send(str(public_key_controll).encode("utf-8"))             # Send Controll_pc public key to hmac_pc

        HMAC_PK = int(DH[1])                                            # hmac pc public key
        shared_session_key = (HMAC_PK ** private_key) % q               # Shared secret key, 
        key = bytes(BBS(shared_session_key), "latin-1")                 # Generate a more secure key with blumblumshub, session key as seed
        print("Shared sesion key = ", key)
        buffer_HMAC = hmac.new(key, b'', hashlib.sha256,)
        single_HMAC = hmac.new(key, b'', hashlib.sha256,)
        Z = False


while True:
    clientsocket,addr = controll_pc.accept()
    #print("Got a connection from %s" % str(addr))
    msg = clientsocket.recv(1024)

    if addr[1] == 8052 and msg_counter >= 500:
        print("buffer hmac_pc calcualted HMAC:     ", msg.decode("utf-8"))
        print("buffer controll_pc calculated HMAC: ", buffer_HMAC.hexdigest())
        if buffer_HMAC.hexdigest().encode("utf-8") == msg:
            print("buffer HMAC match \n")

            buffer_HMAC = hmac.new(key, b'', hashlib.sha256,)
            msg_counter = 0
        else:
            print("buffer HMAC missmatch! \n")
            buffer_HMAC = hmac.new(key, b'', hashlib.sha256,)
            msg_counter = 0

    elif addr[1] == 8051:
        print("single hmac_pc calcualted HMAC:     ", msg.decode("utf-8"))
        print("single controll_pc calculated HMAC: ", single_HMAC.hexdigest())
        if single_HMAC.hexdigest().encode("utf-8") == msg:
            print("single HMAC match! \n")
            single_HMAC = hmac.new(key, b'', hashlib.sha256,)
        else:
            print("single HMAC missmatch! \n")
            single_HMAC = hmac.new(key, b'', hashlib.sha256,)


    else:
        buffer_HMAC.update(msg)

    msg_counter = msg_counter + 1
