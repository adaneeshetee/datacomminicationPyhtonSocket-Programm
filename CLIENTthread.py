from socket import *

host = "10.5.220.130"
port = 5050

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect((host, port))

# define variables
message_error = "The number is out of range"
message_verfication = " I received all messages thanks "
client_name = "EBISA"  # to call the name of device

# take input number from client
client_number = input("Enter the number you choose : ")
number_int = int(client_number)  # change client_number into integer

while client_socket:
    send_list = f"{client_name},{client_number},{message_verfication},{message_error}"
    client_socket.send(send_list.encode())
    recieve_message = client_socket.recv(1024).decode()
    if (recieve_message == "The number is out of range"):
        print(recieve_message)
        client_socket.send(send_list[3].encode())
        break
    else:

       # print(f"I am {client_name}")
        recieve_list = recieve_message.split(",")
        print(f"The client name is : {client_name}")
        print(f"The server name is : {recieve_list[0]}")
        print(f"The number choosen by client is : {number_int}")
        print(f"The number choosen by the server is : {recieve_list[1]}")
        print(
            f"The sum of client & sever number is : {number_int + int(recieve_list[1])}")
        client_socket.send(send_list[2].encode())
        client_socket.close()
        break
