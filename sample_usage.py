#!/usr/bin/python3


from argparse import ArgumentParser
from connector import Connector, simple_packet_forwarding
from functools import partial


def server_routine(server_conn):
    with server_conn as conn:
        while True:
            data, _ = conn.recvfrom(1500)
            if not data:
                continue
            msg = data.decode("utf-8")
            print("Received by server: {}".format(msg))
            if msg.endswith("exit"):
                break


def client_routine(client_conn, msgs):
    with client_conn as conn:
        for msg in msgs:
            print("Sent by client: ", msg)
            conn.send(msg.encode("utf-8"))


def parse_args():
    parser = ArgumentParser(description="lol")
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

    Connector = Connector(server_port, middle_port)
    Connector.connect(
        partial(server_routine, server_conn=Connector.server),
        partial(simple_packet_forwarding, mitm=Connector.mitm),
        partial(client_routine, client_conn=Connector.client, msgs=msgs)
    )
