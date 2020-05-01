import socket
import pandas as pd
import time
from random import randrange
import random


host = socket.gethostname()                                                 # Gets the IP-address of the PC            
hmac_address =  ("127.0.0.1", 8001)                                         # IP address and port of HMAC-PC
controll_address =  ("127.0.0.1", 9001)                                     # Ip address and port of Control-pc
pmu= socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)           # Creates an UDP socket to send from

with open('SVpackets.txt') as f:                                            # Opens txt file with GOOSE messages
    mylist = list(f)                                                        # Creates of the text file
GOOSE_Array =[]                                                             # Creates an empty list
for j in range(0, len(mylist)):                                             # Iterates over the text file, adding each individual GOOSE message as a element to GOOSE_Array 
    if j % 18 == 0:                                                          
        packet = ""
        for i in range(j, j+17):
            packet = packet + mylist[i]
        GOOSE_Array.append(packet)
length = len(GOOSE_Array)

for i in range(0, length):                                                  # For each GOOSE msg DO:
    #random.seed(i)
    #randval = random.randrange(0,100) 
    if i > 1250 and i < 1500:
        pmu.sendto(str.encode(GOOSE_Array[i]), controll_address)            # Sends a packet to controll pc
    else:
        pmu.sendto(str.encode(GOOSE_Array[i]), hmac_address)                # Sends a packet to hmac pc
        pmu.sendto(str.encode(GOOSE_Array[i]), controll_address)            # Sends a packet to controll pc
    if i% 250 == 0:
        print("\n", i, "GOOSE messages sent to both HMAC and controll PC")  # Print to keep track of nr of packets sent
    time.sleep(0.01)                                                        # max rate of PMU GOOSE messages           
print("Program finished")
