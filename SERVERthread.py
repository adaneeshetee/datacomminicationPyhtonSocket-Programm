from socket import *

host = "0.0.0.0"
port = 5050

server_socket = socket(AF_INET, SOCK_STREAM)
server_socket.bind((host, port))
server_socket.listen()

server_name = "YENADA"  # to call the name of the device
print(f"{server_name} is listening ...")

while True:
    connection, address = server_socket.accept()
    recieved_message = connection.recv(1024).decode()
    recieve_list = recieved_message.split(",")

    if (int(recieve_list[1]) <= 100 and int(recieve_list[1]) >= 0):

        server_number = 77  # its random number of server
        print(f"The server name is : {server_name}")
        print(f"The client name is : {recieve_list[0]}")
        print(f"The number choosen by the client is : {recieve_list[1]}")
        print(f"The number choosen by server is : {server_number}")
        print(
            f"The sum of client & server number is : {server_number + int(recieve_list[1])}")

        send_data = f"{server_name},{server_number}"
        connection.send(send_data.encode())
        print(f'verification from client : {recieve_list[2]}')
        print(f'--------------------')
        print("I am listening for other clients now....")
        connection.close()
    else:
        send_data = "The number is out of range"
        connection.send(send_data.encode())
        print(recieve_list[3])
        connection.close()
        break
