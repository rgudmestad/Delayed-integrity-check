import socket
from time import sleep

host = socket.gethostname()                   
hmac_address =  ("127.0.0.1", 8001)                     
controll_address =  ("127.0.0.1", 9001)
pmu= socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# PMU.py sends a message to both hmac_pc and controll_pc each 0.015 second. 
# Each message consists of:  {"id + "test"} e.g. {1 "test"}, {2 "test"} etc...
for i in range(0, 10001):
    value = str(i) + " test"
    GOOSE = str.encode(value)
  
    pmu.sendto(GOOSE, hmac_address)
    pmu.sendto(GOOSE, controll_address)

    if i% 1000 == 0:
        print(i, " GOOSE messages sent to both HMAC and controll PC")
    #sleep(0.015) # max rate of PMU GOOSE messages
    
print("finito!")
