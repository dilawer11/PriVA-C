import logging
import socket
import traceback

class DefendedSocket:
    def __init__(self, end_type, addr, port):
        self.l = logging.getLogger('DefendedSocket')
        self.l.info("Initializing DefendedSocket")
        self.addr = addr
        self.port = port
        self.end_type = end_type
        self.connect()
    
    def connect(self):
        if self.end_type == 'Client':
            self.client()
        elif self.end_type == 'Server':
            self.server()
        else:
            raise ValueError("Invalid End Type")
        return

    def client(self):
        self.defended_socket = None
        self.l.info(f"Connecting to {self.addr}:{self.port}")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.addr, self.port))
        print("DefendedSocket: Connected to ServerProxy", flush=True)
        self.l.info(f"Connected to {self.addr}:{self.port}")
        self.defended_socket = s
        return
    
    def server(self):
        server_socket = None
        self.l.info(f"Binding to {self.addr}:{self.port}")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.addr, self.port))
        server_socket = s
        self.l.info(f"Listening on {self.addr}:{self.port}")
        print("DefendedSocket: Listening", flush=True)
        server_socket.listen(1)
        self.defended_socket, client_addr = server_socket.accept()
        self.l.info(f"Connected to {client_addr}")
        print(f"DefendedSocket: Connected to {client_addr}", flush=True)
        return

    def send(self, data, retry=True):
        self.defended_socket.send(data)
        self.l.debug(f"send {len(data)} bytes")


    def recv(self, size, retry=True):
        data = self.defended_socket.recv(size)
        self.l.info(f"recv {len(data)} bytes")
        return data
        
    def close(self):
        self.defended_socket.close()
        return