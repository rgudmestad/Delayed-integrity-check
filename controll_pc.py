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

msg_counter = 0                                         # Counter for the number of received messages from the PMU
q = 2971                                                # Diffe-Hellman public parameter
g = 3                                                   # Diffe-Hellman public parameter
key_exchange = True                                     # used to initaiate DH key exhange


def BBS(seed):                                          # Blum Blum Shib algorithm to generate cryptographicly secure pseudorandom number generator
    key_length = 254                                    # Algorithm taken from Cryptography and Network Security Principles and Practices, 
    q = 32452843                                        # Fourth Edition Cryptography and Network Security Principles and Practices, Fourth Edition
    p = 15485863
    M = q*p 
    key = ''
    for i in range(0, key_length):                      #BBS formumla realization
        seed = (seed**2)%M
        bit = seed & 1                                  #Bit selection method; keeping only the LSB
        key += str(bit)
    key = hex(int(key, 2))                              #Transforming the binary key to hex-dec
    return key



while key_exchange:
    clientsocket,addr = controll_pc.accept()
    msg = clientsocket.recv(1024)
    
    # Diffie-Hellman secure key exchange. Initiated by HMAC_pc
    if addr[1] == 8052 and msg.decode("utf-8").__contains__("key"):         # keyword "key" is used to identify the DH key exchange
        DH = msg.decode("utf-8").split(' ')                                 # DH[1] = hmac pc public key
        private_key = randrange(10000)                                      # Controll_PC private key
        public_key_controll = (g ** private_key) % q                        # Controll_PC public key
        print("Public key calculated and sent to HMAC PC ")

        send_key = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        send_key.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        send_key.bind((host, 9050))
        send_key.connect((host, hmac_pc_port))
        send_key.send(str(public_key_controll).encode("utf-8"))             # Send Controll_pc public key to hmac_pc

        HMAC_PK = int(DH[1])                                                # hmac pc public key
        shared_session_key = (HMAC_PK ** private_key) % q                   # Shared secret key, 
        key = bytes(BBS(shared_session_key), "latin-1")                     # Generate a longer and more secure key with blumblumshub algorithm, session key as seed
        print("Shared session key established! \n")
        buffer_HMAC = hmac.new(key, b'', hashlib.sha256,)                   # Set BBS generated key as HMAC key
        single_HMAC = hmac.new(key, b'', hashlib.sha256,)                   # Set BBS generated key as HMAC key
        key_exchange = False


# Handels messages from the PMU and hmacs from the HMAC pc 
while True:
    clientsocket,addr = controll_pc.accept()
    msg = clientsocket.recv(1024)

# PMU messages 
    if addr[1] != 8051:
        if addr[1] != 8052:                                                             # If the controll PC receives data from the PMU do:
            get_id = msg.decode("utf-8").split(' ')                                     # Split the message to extract the PMU-message ID
            ID = int(get_id[0])                                                         # message ID
            ID = ID + 250
            buffer_HMAC.update(msg)                                                     # Updates the hmac for each message received from the PMU
            msg_counter = msg_counter + 1                                               # Update message counter
            if ID % 500 == 0:                                                           
                single_HMAC = hmac.new(key, b'', hashlib.sha256,) 
                single_HMAC.update(msg)                                                 # calculate a hmac for a single messages. Does this for each message that has a id that is dividable by 500
                print("HMAC for ID: ", ID, " calculated")

# Buffer hmac messages
    if addr[1] == 8052 and msg_counter == 500:                                          # Checks if the HMAC for the last 1000 PMU messages match
        print("HMAC's for the last 500 messages:")
        print("HMAC_PC calcualted HMAC:     ", msg.decode("utf-8"))
        print("Controll_PC calculated HMAC: ", buffer_HMAC.hexdigest())
        if buffer_HMAC.hexdigest().encode("utf-8") == msg:
            print("Buffer HMAC match \n")                                               # Print if match
        else:
            print("Buffer HMAC missmatch! \n")                                          # Print if missmatch
        buffer_HMAC = hmac.new(key, b'', hashlib.sha256,)                               # Resets the hmac
        msg_counter = 0
        

# Single hmac messages
    if addr[1] == 8051:                                                                 # Receive single message hmacs from the HMAC PC
        print("Single hmac_pc calcualted HMAC:     ", msg.decode("utf-8"))          
        print("Single controll_pc calculated HMAC: ", single_HMAC.hexdigest())
        if single_HMAC.hexdigest().encode("utf-8") == msg:                              # Check if the hmac for the single message matches
            print("Single HMAC match! \n")                                              # print if match                
        else:
            print("Single HMAC missmatch! \n")                                          # print if missmatch