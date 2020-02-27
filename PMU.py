import socket
from time import sleep

host = socket.gethostname()                           
hmac_pc_port = 8000                        
controll_pc_port = 9000
#x = True
messages = []






# PRØV UDP!!!! socket.SOCK_DGRAM 

# PMU.py sends a message to both hmac_pc and controll_pc each 0.015 second. 
# Each message consists of:  {"id + "test"} e.g. {1 "test"}, {2 "test"} etc...
for i in range(0, 3000):
    value = str(i) + " test"

    pmu_to_hmac_pc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    pmu_to_hmac_pc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #pmu_to_hmac_pc.bind((host, 6800))
    pmu_to_hmac_pc.connect((host, hmac_pc_port))
    pmu_to_hmac_pc.send(value.encode("utf-8"))
    pmu_to_hmac_pc.shutdown(socket.SHUT_RDWR)
    pmu_to_hmac_pc.close()  


    pmu_to_controll_pc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    pmu_to_controll_pc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #pmu_to_controll_pc.bind((host, 6700)) 
    pmu_to_controll_pc.connect((host, controll_pc_port))
    pmu_to_controll_pc.send(value.encode("utf-8"))
    pmu_to_controll_pc.shutdown(socket.SHUT_RDWR)
    pmu_to_controll_pc.close()

    if i% 250 == 0:
        print(i, " GOOSE messages sent to both HMAC and controll PC")
    sleep(0.015) # max rate of PMU GOOSE messages
    
print("finito!")
