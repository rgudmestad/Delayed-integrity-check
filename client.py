import socket
import hmac
import hashlib


HMAC = hmac.new(b'test', b'', hashlib.sha256,)
messages = ["Mitt ","navn ","er ","Racin ","Gudmestad "]

host = socket.gethostname()                           
port = 9999

while True:
    value = input("Type 1 to send GOOSE. Type 2 to send HMAC: ")

    if value == "1":
        pmu = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        pmu.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   
        pmu.bind((host, 7005))
        pmu.connect((host, port))
        for i in range(len(messages)):
            pmu.send(messages[i].encode("utf-8"))
            HMAC.update(messages[i].encode("utf-8"))          
        pmu.close()

    if value == "2":
        hmac_pc = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        hmac_pc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   
        hmac_pc.bind((host, 8005))
        hmac_pc.connect((host, port))    
        hmac_pc.send(HMAC.hexdigest().encode("utf-8"))
        HMAC = hmac.new(b'test', b'', hashlib.sha256,)
        hmac_pc.close()


