import socket
from time import sleep

host = socket.gethostname()                           
hmac_pc_port = 8000                        
controll_pc_port = 9000
#x = True
messages = []

for i in range(0, 2000):
    value = str(i) + " test"
    pmu_to_hmac_pc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    pmu_to_hmac_pc.connect((host, hmac_pc_port))
    pmu_to_hmac_pc.send(value.encode("utf-8"))   

    pmu_to_controll_pc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    pmu_to_controll_pc.connect((host, controll_pc_port))
    
    pmu_to_controll_pc.send(value.encode("utf-8"))
    if i% 250 == 0:
        print(i, " GOOSE messages sent to both HMAC and controll PC")
    sleep(0.015) # max rate of PMU GOOSE messages
    
print("finito!")