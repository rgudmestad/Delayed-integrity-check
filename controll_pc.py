import socket       
import hmac
import hashlib

controll_pc = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
host = socket.gethostname()                           
port = 9000        
controll_pc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)                             
controll_pc.bind((host, port))                                  
controll_pc.listen(10)   
buffer_HMAC = hmac.new(b'test', b'', hashlib.sha256,)
single_HMAC = hmac.new(b'test', b'', hashlib.sha256,)
msg_counter = 0

while True:
    clientsocket,addr = controll_pc.accept()
    #print("Got a connection from %s" % str(addr))
    msg = clientsocket.recv(1024)
    

    if addr[1] == 8052 and msg_counter >= 500:
        print("buffer hmac_pc calcualted HMAC:     ", msg.decode("utf-8"))
        print("buffer controll_pc calculated HMAC: ", buffer_HMAC.hexdigest())
        if buffer_HMAC.hexdigest().encode("utf-8") == msg:
            print("buffer HMAC match \n")

            buffer_HMAC = hmac.new(b'test', b'', hashlib.sha256,)
            msg_counter = 0
        else:
            print("buffer HMAC missmatch! \n")
            buffer_HMAC = hmac.new(b'test', b'', hashlib.sha256,)
            msg_counter = 0

    elif addr[1] == 8051:
        print("single hmac_pc calcualted HMAC:     ", msg.decode("utf-8"))
        print("single controll_pc calculated HMAC: ", single_HMAC.hexdigest())
        if single_HMAC.hexdigest().encode("utf-8") == msg:
            print("single HMAC match! \n")
            single_HMAC = hmac.new(b'test', b'', hashlib.sha256,)
        else:
            print("single HMAC missmatch! \n")
            single_HMAC = hmac.new(b'test', b'', hashlib.sha256,)


    else:
        buffer_HMAC.update(msg)

    msg_counter = msg_counter + 1
