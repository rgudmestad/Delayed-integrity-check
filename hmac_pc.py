import socket       
import hmac
import hashlib

host = socket.gethostname()                           
port = 8000            
hmac_pc = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
hmac_pc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)                             
hmac_pc.bind((host, port))                                  
hmac_pc.listen(10)
buffer_HMAC = hmac.new(b'test', b'', hashlib.sha256,)
single_HMAC = hmac.new(b'test', b'', hashlib.sha256,)
controll_pc_port = 9000

msg_counter = 0

while True:
    clientsocket,addr = hmac_pc.accept()
    #print("Got a connection from %s" % str(addr))
    msg = clientsocket.recv(1024)
    #print("Message from the PMU: ", msg.decode("utf-8"))
    buffer_HMAC.update(msg)

    get_id = msg.decode("utf-8").split(' ')
    ID = int(get_id[0])
    if msg_counter >= 1000:
        print("calculated buffer HMAC :", buffer_HMAC.hexdigest())
        send_to_controll = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        send_to_controll.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        send_to_controll.bind((host, 8052))
        send_to_controll.connect((host, controll_pc_port))
        send_to_controll.send(buffer_HMAC.hexdigest().encode("utf-8"))      
        #send_to_controll.close()
        #clientsocket.close()
        buffer_HMAC = hmac.new(b'test', b'', hashlib.sha256,)
        msg_counter = 0

    if ID % 500 == 0:
        print("calculated single HMAC :", single_HMAC.hexdigest())
        send_to_controll = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        send_to_controll.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        send_to_controll.bind((host, 8051))
        send_to_controll.connect((host, controll_pc_port))
        send_to_controll.send(single_HMAC.hexdigest().encode("utf-8"))      
        #send_to_controll.close()
        #clientsocket.close()
        single_HMAC = hmac.new(b'test', b'', hashlib.sha256,)
        
        

    msg_counter = msg_counter + 1