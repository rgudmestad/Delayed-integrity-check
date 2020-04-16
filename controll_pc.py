import socket       
import hmac
import hashlib
from random import randrange
import math

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
PMU_msg = controll_UDP.recvfrom(1024)                                           # Listen for PMU messages

msg_counter = 0                                                                 # Counter for the number of received messages from the PMU
q = 2971                                                                        # Diffe-Hellman public parameter
g = 3                                                                           # Diffe-Hellman public parameter
key_exchange = True                                                             # Used to initaiate DH key exhange

def BBS(seed):                                                                  # Blum Blum Shib algorithm to generate cryptographicly secure pseudorandom number generator
    key_length = 254                                                            # Algorithm taken from Cryptography and Network Security Principles and Practices, 
    q = 32452843                                                                # Fourth Edition Cryptography and Network Security Principles and Practices, Fourth Edition
    p = 15485863
    M = q*p 
    key = ''
    for i in range(0, key_length):                                              #BBS formumla realization
        seed = (seed**2)%M
        bit = seed & 1                                                          #Bit selection method; keeping only the LSB
        key += str(bit)
    key = hex(int(key, 2))                                                      #Transforming the binary key to hex-dec
    return key


# Diffie-Hellman secure key exchange. Initiated by HMAC_pc
while key_exchange:
    clientsocket,addr = controll_pc.accept()
    msg = clientsocket.recv(1024)
    
    if addr[1] == 8053 and msg.decode("utf-8").__contains__("key"):                     # Listens for a message from hmac_pc, with the word "key" in it
        DH = msg.decode("utf-8").split(' ')                                             # DH[1] = hmac pc public key
        private_key = randrange(10000)                                                  # Controll_PC private key
        public_key_controll = (g ** private_key) % q                                    # Controll_PC public key
        print("Public key calculated and sent to HMAC PC ")

        send_key = socket.socket(socket.AF_INET, socket.SOCK_STREAM)                    # sets up and binds an IP address/Port used to send the public key to hmac_PC
        send_key.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)                  # sets up and binds an IP address/Port used to send the public key to hmac_PC
        send_key.bind((host, 9050))                                                     # Binds an IP address/Port used to send the public key to hmac_PC
        send_key.connect((host, hmac_pc_port))                                          # Establish connection to hmac_PC
        send_key.send(str(public_key_controll).encode("utf-8"))                         # Send Controll_pc public key to hmac_pc

        HMAC_PK = int(DH[1])                                                            # hmac pc public key
        shared_session_key = (HMAC_PK ** private_key) % q                               # Shared secret key, 
        key = bytes(BBS(shared_session_key), "latin-1")                                 # Generate a longer and more secure key with blumblumshub algorithm, session key as seed
        print("Shared session key established! \n")
        buffer_HMAC = hmac.new(key, b'', hashlib.sha256,)                               # Set BBS generated key as HMAC key
        single_HMAC = hmac.new(key, b'', hashlib.sha256,)                               # Set BBS generated key as HMAC key
        key_exchange = False

# Handels messages from the PMU and hmacs from the HMAC pc 
while True:
    datagram = controll_UDP.recvfrom(1024)                                              # Listens for UDP messages from the pmu and hmac_pc
    msg = format(datagram[0])                                                           # Msg payload

# PMU message handler
    if  (msg.__contains__("buffer") == False):
        if (msg.__contains__("single") == False):                                        
            #ID = msg.replace("No.,","")
            #ID = ID.split("Time")                                                        # Split the message to extract the PMU-message ID
            #ID = ID[0]
            #ID = ID.replace("b'","")
            ID = str.encode(msg)
            ID = ID.decode("utf-8")
            ID = ID.split("Frame ")[1].split(":")[0]
            ID = int(ID)                                                                 # PMU message ID
            ID = ID + 250
            buffer_HMAC.update(msg.encode("utf-8"))                                      # Update the hmac with the new PMU message
            msg_counter = msg_counter + 1                                                # Update message counter
            if ID % 500 == 0:                                                            # Generates a single hmac for each 500th message
                single_HMAC = hmac.new(key, b'', hashlib.sha256,)                        # Reset the hmac
                single_HMAC.update(msg.encode("utf-8"))                                  # calculate a hmac for a single messages
                print("Single HMAC for ID: ", ID, " calculated ")

# HMAC_pc buffer hmac message handler
    if msg.__contains__("buffer"):                                                       # Checks if the message is a buffer hmac
        hmac_buffer = msg.replace("buffer","")                                           # Message formating
        hmac_buffer = hmac_buffer.replace("b' ","")
        hmac_buffer = hmac_buffer.replace("'","")
        print("HMAC's for the last 500 messages:")
        print("HMAC_PC calcualted HMAC for ID:          ", ID, " "     ,hmac_buffer)
        print("Controll_PC calculated HMAC for ID:      ", ID, " "     ,buffer_HMAC.hexdigest())
        if buffer_HMAC.hexdigest() == hmac_buffer:                                      # Check if hmac_pc and controll_pc have generated identical hmac's
            print("Buffer HMAC match \n")                                               # Print if match
        else:
            print("Buffer HMAC missmatch! \n")                                          # Print if missmatch
        buffer_HMAC = hmac.new(key, b'', hashlib.sha256,)                               # Resets the hmac
        msg_counter = 0                                                                 # Reset msg counter
        continue                                                                        # Jump to next iteration

# HMAC_pc single hmac message handler
    if msg.__contains__("single"):                                                      # Checks if the message is a single hmac
        hmac_single = msg.replace("single","")                                          # Message formating
        hmac_single = hmac_single.replace("b' ","")
        hmac_single = hmac_single.replace("'","")
        print("Single hmac_pc calcualted HMAC for ID:       ", ID, " "     ,hmac_single)          
        print("Single controll_pc calculated MAC for ID:    ", ID, " "     ,single_HMAC.hexdigest())
        if single_HMAC.hexdigest() == hmac_single:                                      # Check if mac_pc and controll_pc have generated identical hmac's
            print("Single HMAC match! \n")                                              # print if match                
        else:
            print("Single HMAC missmatch! \n")
        continue    


