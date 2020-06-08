import socket       
import hmac
import hashlib
from random import randrange
import math
import random


# sets up and binds an IP address/Port to hmac_pc for Key distribution, Uses TCP
controll_pc = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
host = socket.gethostname()                           
port = 9000        
hmac_pc_port = 8000
controll_pc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)                             
controll_pc.bind((host, port))                                  
controll_pc.listen(10)   
controll_UDP = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)     # Controll_pc UDP socket
controll_UDP.bind(("127.0.0.1", 9001))                                          # Address of the UDP lister for controll PC

buffer_string = ""                                                              # holds the buffered GOOSe messages
firstID = 1
single_dict = {}
msg_counter = 0                                                                 # Counter for the number of received messages from the PMU
q = 2971                                                                        # Diffe-Hellman public parameter
g = 3                                                                           # Diffe-Hellman public parameter
key_exchange = True                                                             # Used to initaiate DH key exhange
Buffer_missmatch = 0
Buffer_count = 0
Single_missmatch = 0
Single_count = 0

def BBS(seed, key_length):                                                      # Blum Blum Shib algorithm to generate cryptographicly secure pseudorandom number generator 
    q = 32452843                                                                # Algorithm taken from Cryptography and Network Security Principles and Practices
    p = 15485863                                                                # Fourth Edition Cryptography and Network Security Principles and Practices, Fourth Edition
    M = q*p 
    key = ''
    for i in range(0, key_length):                                              #BBS formumla realization
        seed = (seed**2)%M
        bit = seed & 1                                                          #Bit selection method; keeping only the LSB
        key += str(bit)
    key = int(key, 2)                                                           #Transforming the binary key to hex-dec
    return key


# Diffie-Hellman secure key exchange. Initiated by HMAC_pc
while key_exchange:
    clientsocket,addr = controll_pc.accept()
    msg = clientsocket.recv(1024)
    
    if addr[1] == 50053 and msg.decode("utf-8").__contains__("key"):                    # Listens for a message from hmac_pc, with the word "key" in it
        DH = msg.decode("utf-8").split(' ')                                             # DH[1] = hmac pc public key
        private_key = randrange(10000)                                                  # Controll_PC private key
        public_key_controll = (g ** private_key) % q                                    # Controll_PC public key
        print("\n Public key calculated and sent to HMAC PC ")
        send_key = socket.socket(socket.AF_INET, socket.SOCK_STREAM)                    # sets up and binds an IP address/Port used to send the public key to hmac_PC
        send_key.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)                  # sets up and binds an IP address/Port used to send the public key to hmac_PC
        send_key.bind((host, 50050))                                                    # Binds an IP address/Port used to send the public key to hmac_PC
        send_key.connect((host, hmac_pc_port))                                          # Establish connection to hmac_PC
        send_key.send(str(public_key_controll).encode("utf-8"))                         # Send Controll_pc public key to hmac_pc
        HMAC_PK = int(DH[1])                                                            # hmac pc public key
        shared_session_key = (HMAC_PK ** private_key) % q                               # Shared secret key,
        RandomKey = shared_session_key 
        random.seed(RandomKey)
        randval = random.randrange(0,250)    
        key = BBS(shared_session_key, 20)                                               # Generate a longer and more secure key with blumblumshub algorithm, session key as seed
        print(" Shared session key established! \n")
        single_HMAC = hmac.new(bytes(key), b'', hashlib.sha256,)                        # Set BBS generated key as HMAC key
        key_exchange = False

# Handels messages from the PMU and hmacs from the HMAC pc 
while True:
    datagram = controll_UDP.recvfrom(1024)                                              # Listens for UDP messages from the pmu and hmac_pc
    msg = format(datagram[0])                                                           # Msg payload

# PMU message handler
    if  (msg.__contains__("buffer") == False):
        if (msg.__contains__("single") == False):                                        
            ID = str.encode(msg)
            ID = ID.decode("utf-8")
            ID = ID.split("Frame ")[1].split(":")[0]
            ID = int(ID)                                                                 # PMU message ID
            realID = 0
            if ID % 2 == 1:
                ID = ID + 1
                realID = 1
            buffer_string = buffer_string + msg
            msg_counter = msg_counter + 1                                               # Update message counter
            if ID % randval == 0:                                                       # Generates a single hmac for each 500th message
                single_HMAC = hmac.new(bytes(key), b'', hashlib.sha256,)                # Reset the hmac
                single_HMAC.update(msg.encode("utf-8"))                                 # calculate a hmac for a single messages
                single_dict[ID-realID] = single_HMAC.hexdigest()
                Single_count = Single_count + 1

# HMAC_pc buffer hmac message handler
    if msg.__contains__("buffer"):                                                      # Checks if the message is a buffer hmac
        buffer_HMAC = hmac.new(bytes(key), buffer_string.encode("utf-8"), hashlib.sha256,) # Create a buffer-HMAC
        buffer_string = ""                                                              # resets the HMAC buffer
        Buffer_count = Buffer_count + 1
        hmac_buffer = msg.replace("buffer","")                                          # Message formating
        hmac_buffer = hmac_buffer.replace("b' ","")
        hmac_buffer = hmac_buffer.replace("'","")
        print("=================Buffer-HMAC===================")
        print("Buffer-HMAC for ID", firstID,"-", ID-realID)
        firstID = ID-realID
        if buffer_HMAC.hexdigest() == hmac_buffer:                                      # Check if hmac_pc and controll_pc have generated identical hmac's
            print("MATCH")                                                              # Print if match
        else:
            print("MISS")                                                               # Print if missmatch
            Buffer_missmatch = Buffer_missmatch + 1
        print("Buffer missmatch rate: ", (Buffer_missmatch/Buffer_count)*100,"%     I" )
        buffer_HMAC = hmac.new(bytes(key), b'', hashlib.sha256,)                        # Resets the hmac
        msg_counter = 0                                                                 # Reset msg counter
        print("===============================================\n")
        continue                                                                        # Jump to next iteration

# HMAC_pc single hmac message handler
    if msg.__contains__("single"):                                                      # Checks if the message is a single hmac
        hmac_single = msg.replace("single","")                                          # Message formating
        hmac_single = hmac_single.replace("b' ","")
        hmac_single = hmac_single.replace("'","")
        checked_keys = []
        print("-----------------Single-HMAC-------------------")
        for k, v in single_dict.items():
            if hmac_single == v:
                print("MATCH for ID:", k)                                               # print if match
                RandomKey = int(BBS(RandomKey, 5))
                random.seed(RandomKey)
                randval = random.randrange(0,250)   
            else:
                Single_missmatch = Single_missmatch + 1
                print("MISS for ID: ", k)
        print("Single missmatch rate: ", (Single_missmatch/Single_count)*100,"%")
        print("-----------------------------------------------")
        delete = []
        for k, v in single_dict.items(): 
            delete.append(k)
        for i in delete: 
            del single_dict[i]  
        continue    


