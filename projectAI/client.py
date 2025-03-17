import socket

def start_client():
    host = "192.168.242.115" # Server IP (can be local or remote IP)
    port = 12345        # Port number matching the server

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    while True:
        message = input("Enter message: ")
        client_socket.send(message.encode())  # Send the message to the server

        if message.lower() == 'exit':
            break

    client_socket.close()

if __name__ == '__main__':
    start_client()
