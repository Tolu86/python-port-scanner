import socket

HOST = "127.0.0.1"
PORT = 9999

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_REUSEADDR,
    1
)

server.bind((HOST, PORT))

server.listen(5)

print(f"Test server listening on {HOST}:{PORT}", flush=True)

while True:

    client, address = server.accept()

    print(f"Connection received from {address}", flush=True)

    banner = "TEST-SERVER/1.0 Port-Scanner-Lab\r\n"

    client.sendall(banner.encode())

    client.close()