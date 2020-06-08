# Delayed-integrity-check
 

The figure shows how the solution works: 
  - PMU.py represents a PMU sending GOOSE messages
  
  - hmac-PC.py represents a computer that subcribes to messages from the OMU, and makes HMACS with the messages as input.

  - control-pc.py represents a computer that also subscribes to GOOSE messages from the PMU. It recives HMACs from the hmac-pc and   compares them against the the HMAC it has generated itself.
  
![Master-Page-1](https://user-images.githubusercontent.com/52523429/73828213-2455ee80-4801-11ea-9bd7-66760f7065b4.png)

To run the code, open 3 diffrent cmd/powershell windows. run the scripts in the following order:
 1. control_pc.py
 2. hmac_pc.py
 3. PMU.py

remember to have the dataset (packets.txt) in the same folder as PMU.py

SIDENOTE: packets.txt only contain 20% of the data from that was used on the original dataset, due to file-size constraint on Github
