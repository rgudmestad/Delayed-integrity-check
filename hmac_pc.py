import socket       
import hmac
import hashlib
from random import randrange


# sets up and binds an IP address/Port to hmac_pc
host = socket.gethostname()                           
port = 8000            
hmac_pc = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
hmac_pc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)                             
hmac_pc.bind((host, port))                                  
hmac_pc.listen(10)
controll_pc_port = 9000

msg_counter = 0                                         # Counter for the number of received messages from the PMU
q = 2971                                                # Diffe-Hellman public parameter
g = 3                                                   # Diffe-Hellman public parameter
key_exchange = True                                     # used to initaiate DH key exhange
DH = True                                               # used to initaiate DH key exhange

def BBS(seed):                                          # Blum Blum Shib algorithm to generate cryptographicly secure pseudorandom number generator
    key_length = 254                                    # Algorithm taken from Cryptography and Network Security Principles and Practices, 
    q = 32452843                                        # Fourth Edition Cryptography and Network Security Principles and Practices, Fourth Edition
    p = 15485863
    M = q*p                                             # q mod(3) == p mod(3)
    key = ''
    for i in range(0, key_length):                      # BBS formumla realization
        seed = (seed**2)%M
        bit = seed & 1                                  # Bit selection method; keeping only the LSB
        key += str(bit)
    key = hex(int(key, 2))                              # Transforming the binary key to hex-dec
    return key


# Diffe-Hellman key exchange:
while key_exchange:
    clientsocket,addr = hmac_pc.accept()
    msg = clientsocket.recv(1024)
    
    if DH == True:                                                                          # Checks if a public key has been created and sent to controll_PC, if not DO:
        private_key = randrange(10000)                                                      # Generate private key
        public_key_hmac = (g ** private_key) % q                                            # Generate public key
        print("Public and sent to Controll PC")

        send_to_controll = socket.socket(socket.AF_INET, socket.SOCK_STREAM)                # sets up and binds an IP address/Port used to send the public key to controll_PC
        send_to_controll.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)              # sets up and binds an IP address/Port used to send the public key to controll_PC
        send_to_controll.bind((host, 8052))                                                 # Binds an IP address/Port used to send the public key to controll_PC
        send_to_controll.connect((host, controll_pc_port))                                  # Establish connection to controll_PC
        HMAC_PK = "key " + str(public_key_hmac)                                             # Create the message 'key public hmac key' 
        send_to_controll.send(HMAC_PK.encode("utf-8"))                                      # Send public key to controll PC
        DH = False  

    if addr[1] == 9050:                                                                     # Checks if controll_pc have answered with a public key, if it has, DO:
        controll_PK = int(msg.decode("utf-8"))                                              # Exctract the controll_pc public key and create a shared session key
        shared_session_key = (controll_PK ** private_key) % q                               # Shared secret key, 
        key = bytes(BBS(shared_session_key), "latin-1")                                     # Generate a longer and more secure key with blumblumshub algorithm, session key as seed
        print("Shared sesion established! \n")
        buffer_HMAC = hmac.new(key, b'', hashlib.sha256,)                                   # Set BBS generated key as HMAC key
        single_HMAC = hmac.new(key, b'', hashlib.sha256,)                                   # Set BBS generated key as HMAC key
        key_exchange = False    


# Handels messages from the PMU and hmacs to the controll pc
while True:
    clientsocket,addr = hmac_pc.accept()
    msg = clientsocket.recv(1024)
    
# PMU messages
    get_id = msg.decode("utf-8").split(' ')                                                 # Split the message to extract the PMU-message ID
    ID = int(get_id[0]) 
    ID = ID + 250                                                                           # PMU message ID
    buffer_HMAC.update(msg)                                                                 # Update the hmac with the new PMU message
    msg_counter = msg_counter + 1                                                           # Increments the message counter.

# Buffer hmac messages
    if msg_counter == 500:                                                                  # Generates a HMAC based on the 1000 last PMU messages
        print("Calculated Buffer HMAC :", buffer_HMAC.hexdigest(), "\n")
        send_to_controll = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        send_to_controll.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        send_to_controll.bind((host, 8052))
        send_to_controll.connect((host, controll_pc_port))
        send_to_controll.send(buffer_HMAC.hexdigest().encode("utf-8"))                      # Sends the HMAC to the controll PC
        buffer_HMAC = hmac.new(key, b'', hashlib.sha256,)                                   # Resets the HMAC
        msg_counter = 0                                                                     # Resets the message counter

# Single hmac messages
    if ID % 500 == 0:                                                                       # Sends a HMAC based on an indivudual PMU message. Does this for each 500th message (uses ID to identify the message)
        single_HMAC = hmac.new(key, b'', hashlib.sha256,)                                   # Resets the HMAC
        single_HMAC.update(msg)
        print("Calculated Single HMAC :", single_HMAC.hexdigest(), "for msg with ID: ", ID, "\n")
        send_to_controll = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        send_to_controll.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        send_to_controll.bind((host, 8051))
        send_to_controll.connect((host, controll_pc_port))
        send_to_controll.send(single_HMAC.hexdigest().encode("utf-8"))                      # Sends the HMAC to the controll PC