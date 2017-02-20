#!/usr/bin/python3


import argparse
import socket
from contextlib import closing
from functools import partial
from tcp_mitm import NoMessages, RecvRoutineStopped, TcpMitm, run_recv
from threading import Thread


def server_routine(port):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", port))
        sock.listen(1)

        conn, addr = sock.accept()
        with closing(conn):
            while True:
                data, _ = conn.recvfrom(1500)
                if not data:
                    continue
                msg = data.decode("utf-8")
                print("Received by server: {}".format(msg))
                if msg.endswith("exit"):
                    break

    print("Server finished")


def client_routine(server_port, msgs):
    with socket.socket() as sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect(("127.0.0.1", server_port))

        for msg in msgs:
            print("Sent by client: ", msg)
            sock.send(msg.encode("utf-8"))

    print("Client finished")


def recv_any_pkt_from(mitm):
    recvs = [
        (partial(mitm.recv_from_client, block=False), "client"),
        (partial(mitm.recv_from_server, block=False), "server")
    ]

    while True:
        for recv, src in recvs:
            try:
                yield recv(), src
            except NoMessages:
                pass
            continue


def packet_forward(mitm):
    get_pkt = recv_any_pkt_from(mitm)

    while True:
        try:
            pkt, src = next(get_pkt)
        except RecvRoutineStopped:
            break

        if src == "client":
            mitm.send_to_server(pkt)
        elif src == "server":
            mitm.send_to_client(pkt)

    print("Packet forwarding finished")


def parse_args():
    parser = argparse.ArgumentParser(description="lol")
    middle_port_help = "client and server will be sending their messages here"
    middle_port_help += " (I hope you set up dropping RSTs)"
    parser.add_argument("--middle_port", type=int, help=middle_port_help,
                        required=True, metavar="middle_port_num")
    parser.add_argument("--server_port", type=int, help="server port",
                        required=True, metavar="serv_port_num")
    args = parser.parse_args()

    assert_msg = "Server must be listening not on the middle port!"
    assert args.middle_port != args.server_port, assert_msg
    return args


if __name__ == "__main__":
    args = parse_args()
    server_port, middle_port = args.server_port, args.middle_port

    msgs = ["aaaaaaa", "aaaa", "exit"]

    mitm = TcpMitm(server_port, middle_port)
    with run_recv(mitm):
        thr_fwd = Thread(name="pkt_fwd", target=packet_forward, args=(mitm, ))
        thr_server = Thread(name="server", target=server_routine, args=(server_port, ))
        thr_client = Thread(name="client", target=client_routine, args=(middle_port, msgs))

        thr_fwd.start()
        thr_server.start()
        thr_client.start()

        thr_server.join()
        thr_client.join()

    thr_fwd.join()
    print("Main finished")
