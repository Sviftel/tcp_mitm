#!/usr/bin/python3


import socket
from contextlib import closing
from tcp_mitm import TcpMitm
from threading import Thread


def server_routine(port):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", port))
        sock.listen(1)

        conn, addr = sock.accept()
        while True:
            data, _ = conn.recvfrom(1500)
            if not data:
                continue
            msg = data.decode("utf-8")
            print("Received by server: {}".format(msg))
            break
        conn.close()

    print("Server finished")

def client_routine(server_port, msg):
    with socket.socket() as sock:
        sock.connect(("127.0.0.1", server_port))
        sock.send(msg.encode("utf-8"))
    print("Client finished")


def packet_forward(server_port, middle_port):
    with closing(TcpMitm(server_port, middle_port)) as mitm:
        receiver = mitm.recv()
        while True:
            pkt = next(receiver)
            mitm.send(pkt)


if __name__ == "__main__":
    # server_port = 10040
    # msg_len = 5
    # ts = Thread(name="server", target=server_routine, args=(server_port, ))
    # ts.start()
    # tc = Thread(name="client", target=client_routine, args=(server_port, "a" * msg_len))
    # tc.start()

    packet_forward(20040, 10020)

    # tc.join()
    # ts.join()
