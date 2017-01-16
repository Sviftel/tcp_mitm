#!/usr/bin/python3


import socket
import time
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
            if msg == "exit":
                break
        conn.close()

    print("Server finished")


def client_routine(server_port, msgs):
    with socket.socket() as sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect(("127.0.0.1", server_port))

        for msg in msgs:
            sock.send(msg.encode("utf-8"))

    print("Client finished")


def packet_forward(server_port, middle_port):
    with closing(TcpMitm(server_port, middle_port)) as mitm:
        receiver = mitm.recv()
        # i = False

        while True:
            pkt = next(receiver)
            # to check buffer overflowing
            # if not i:
            #     time.Sleep(5)
            #     i = True
            print("Mitm received {} bytes".format(len(pkt)))
            mitm.send(pkt)

    print("Mitm finished")


if __name__ == "__main__":
    server_port = 20040
    middle_port = 10020
    msgs = ["aaaaaaa", "aaaa", "exit"]
    ts = Thread(name="server", target=server_routine, args=(server_port, ))
    ts.start()
    tc = Thread(name="client", target=client_routine, args=(middle_port, msgs))
    tc.start()

    # tm = Thread(name="mitm", target=packet_forward, args=(server_port, middle_port))
    packet_forward(server_port, middle_port)

    tc.join()
    ts.join()
