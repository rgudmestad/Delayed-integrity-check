
import socket

 

localIP         = "127.0.0.1"
localPort       = 20001
bufferSize      = 1024
msgFromServer   = "Hello UDP Client"
bytesToSend     = str.encode(msgFromServer)

 

# Create a datagram socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
# Bind to address and ip
UDPServerSocket.bind((localIP, localPort))
print("UDP server up and listening")

# Listen for incoming datagrams

while(True):
    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    message = bytesAddressPair[0]
    address = bytesAddressPair[1]
    clientMsg = format(message)
    clientIP  = format(address)
    e = clientIP.split(" ")
    print(clientMsg)
    print(e[1])
    print(clientIP)
    # Sending a reply to client
    UDPServerSocket.sendto(bytesToSend, address)

    clientMsg = clientMsg.split(" ")
    if clientMsg[0].__contains__("buff"):
        print("hmac buffer")
    if clientMsg[0].__contains__("single"):
        print("hmac single")
