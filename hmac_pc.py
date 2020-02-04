import socket       
import hmac
import hashlib
from random import randrange

host = socket.gethostname()                           
port = 8000            
hmac_pc = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
hmac_pc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)                             
hmac_pc.bind((host, port))                                  
hmac_pc.listen(10)

key = bytes("testing",'latin-1')
buffer_HMAC = hmac.new(key, b'', hashlib.sha256,)
single_HMAC = hmac.new(key, b'', hashlib.sha256,)
controll_pc_port = 9000

msg_counter = 0

DH = True
q = 2971
g = 3
Z = True


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


# Diffe-Hellman secure key distrebution
while Z:
    clientsocket,addr = hmac_pc.accept()
    msg = clientsocket.recv(1024)
    
    if DH == True:
        private_key = randrange(10000)
        public_key_hmac = (g ** private_key) % q
        print("public hmac key : ", public_key_hmac)

        send_to_controll = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        send_to_controll.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        send_to_controll.bind((host, 8052))
        send_to_controll.connect((host, controll_pc_port))
        HMAC_PK = "key " + str(public_key_hmac)
        send_to_controll.send(HMAC_PK.encode("utf-8"))
        DH = False
        #Z = False

    if addr[1] == 9050:
        controll_PK = int(msg.decode("utf-8"))                              # DH[1] = controll pc public key
        shared_session_key = (controll_PK ** private_key) % q               # Shared secret key, 
        key = bytes(BBS(shared_session_key), "latin-1")                     # Generate a more secure key with blumblumshub, session key as seed
        print("Shared sesion key = ", key)
        buffer_HMAC = hmac.new(key, b'', hashlib.sha256,)
        single_HMAC = hmac.new(key, b'', hashlib.sha256,)
        Z = False
    
while True:
    clientsocket,addr = hmac_pc.accept()
    #print("Got a connection from %s" % str(addr))
    msg = clientsocket.recv(1024)
    #print("Message from the PMU: ", msg.decode("utf-8"))
    buffer_HMAC.update(msg)

    get_id = msg.decode("utf-8").split(' ')
    ID = int(get_id[0])

    if msg_counter >= 1000:
        print("calculated buffer HMAC :", buffer_HMAC.hexdigest())
        send_to_controll = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        send_to_controll.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        send_to_controll.bind((host, 8052))
        send_to_controll.connect((host, controll_pc_port))
        send_to_controll.send(buffer_HMAC.hexdigest().encode("utf-8"))      
        #send_to_controll.close()
        #clientsocket.close()
        buffer_HMAC = hmac.new(b'test', b'', hashlib.sha256,)
        msg_counter = 0

    if ID % 500 == 0:
        print("calculated single HMAC :", single_HMAC.hexdigest())
        send_to_controll = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        send_to_controll.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        send_to_controll.bind((host, 8051))
        send_to_controll.connect((host, controll_pc_port))
        send_to_controll.send(single_HMAC.hexdigest().encode("utf-8"))      
        #send_to_controll.close()
        #clientsocket.close()
        single_HMAC = hmac.new(b'test', b'', hashlib.sha256,)
        
        

    msg_counter = msg_counter + 1
