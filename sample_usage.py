#!/usr/bin/python3


import socket
from tcp_mitm import RecvRoutineStopped, RunMitm
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
            if msg.endswith("exit"):
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


def packet_forward(mitm):
    while True:
        try:
            pkt = mitm.recv_from_queue()
        except RecvRoutineStopped:
            break

        print("Mitm received {} bytes".format(len(pkt)))
        src_port = pkt["TCP"].sport

        if src_port == mitm.client_port:
            mitm.send_to_server(pkt)
        elif src_port == mitm.server_port:
            mitm.send_to_client(pkt)

    print("Packet forwarding finished")        


if __name__ == "__main__":
    server_port = 20040
    middle_port = 10020
    msgs = ["aaaaaaa", "aaaa", "exit"]


    with RunMitm(server_port, middle_port) as mitm:
        thr_fwd = Thread(name="pkt_fwd", target=packet_forward, args=(mitm, ))
        thr_server = Thread(name="server", target=server_routine, args=(server_port, ))
        thr_client = Thread(name="client", target=client_routine, args=(middle_port, msgs))

        thr_fwd.start()
        thr_server.start()
        thr_client.start()
        # packet_forward(mitm)

        thr_server.join()
        thr_client.join()

    thr_fwd.join()
    print("Main finished")
