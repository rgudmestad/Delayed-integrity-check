import socket
import pandas as pd
import time

host = socket.gethostname()                   
hmac_address =  ("127.0.0.1", 8001)                     
controll_address =  ("127.0.0.1", 9001)
pmu= socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

df = pd.read_csv("wiresharkcapture.csv")                                    # Wireshark capture of IEV 61850 SM traffic, converted into a CVS format
length = df.shape[0]                                                        # length = number of captured packets

for i in range(0, length):
    y = df.iloc[i]                                                          # Formats the CSV file so that it only sends the captured packet, and notthing else 
    y = y.to_string(header=None).split("\n")                                # --"--
    y = [','.join(ele.split()) for ele in y]                                # --"--
    y = "".join(y)                                                          # --"--
    y = str.encode(y)                                                       # --"--
  
    pmu.sendto(y, hmac_address)                                             # Sends a packet to hmac pc
    pmu.sendto(y, controll_address)                                         # Sends a packet to controll pc

    if i% 1000 == 0:
        print(i, " GOOSE messages sent to both HMAC and controll PC")       # Print to keep track of nr of packets sent
    time.sleep(0.01)                                                        # max rate of PMU GOOSE messages       
    
print("finitoo!")


