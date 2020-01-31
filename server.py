import socket       
import hmac
import hashlib

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
host = socket.gethostname()                           
port = 9999          
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)                             
server.bind((host, port))                                  
server.listen(10)           
HMAC = hmac.new(b'test', b'', hashlib.sha256,)

while True:
    clientsocket,addr = server.accept()
    print("Got a connection from %s" % str(addr))
    msg = clientsocket.recv(1024)

    if addr[1] == 7005:
        print("got the message: ", msg.decode("utf-8"))
        HMAC.update(msg)
        clientsocket.close()

    if addr[1] == 8005:
        print("Client calcualted HMAC: ", msg.decode("utf-8"))
        print("Server calculated HMAC: ", HMAC.hexdigest())
        if HMAC.hexdigest() == msg.decode("utf-8"):
            print("HMAC match!")
            HMAC = hmac.new(b'test', b'', hashlib.sha256,)
        else:
            print("HMAC missmatch!")
            HMAC = hmac.new(b'test', b'', hashlib.sha256,)
        clientsocket.close()






