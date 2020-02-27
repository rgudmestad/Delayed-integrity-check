import socket
from time import sleep

host = socket.gethostname() 
serverAddressPort = ("127.0.0.1", 20001)                          
hmac_addresst =  ("127.0.0.1", 8001)                     
controll_address =  ("127.0.0.1", 9001)
#x = True
messages = []


# PRØV UDP!!!! socket.SOCK_DGRAM 

# PMU.py sends a message to both hmac_pc and controll_pc each 0.015 second. 
# Each message consists of:  {"id + "test"} e.g. {1 "test"}, {2 "test"} etc...
for i in range(0, 3000):
    value = str(i) + " test"
    GOOSE = str.encode(value)

    pmu_to_hmac_pc = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    pmu_to_hmac_pc.sendto(GOOSE, hmac_addresst)

    pmu_to_controll_pc = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM) 
    pmu_to_controll_pc.sendto(GOOSE, controll_address)

    if i% 250 == 0:
        print(i, " GOOSE messages sent to both HMAC and controll PC")
    sleep(0.015) # max rate of PMU GOOSE messages
    
print("finito!")
