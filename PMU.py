import socket
import pandas as pd
import time

host = socket.gethostname()                                                 # Gets the IP-address of the PC            
hmac_address =  ("127.0.0.1", 8001)                                         # IP address and port of HMAC-PC
controll_address =  ("127.0.0.1", 9001)                                     # Ip address and port of Control-pc
pmu= socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)           # Creates an UDP socket to send from


with open('SVpackets.txt') as f:
    mylist = list(f)
GOOSE_Array =[]
for j in range(0, len(mylist)):
    if j % 18 == 0:
        packet = ""
        for i in range(j, j+17):
            packet = packet + mylist[i]
        GOOSE_Array.append(packet)
length = len(GOOSE_Array)

for i in range(0, length):
    pmu.sendto(str.encode(GOOSE_Array[i]), hmac_address)                    # Sends a packet to hmac pc
    pmu.sendto(str.encode(GOOSE_Array[i]), controll_address)                # Sends a packet to controll pc
    if i% 1000 == 0:
        print(i, " GOOSE messages sent to both HMAC and controll PC")       # Print to keep track of nr of packets sent
    time.sleep(0.01)                                                        # max rate of PMU GOOSE messages       
    
print("Program finished")


