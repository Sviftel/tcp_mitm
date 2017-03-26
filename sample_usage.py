#!/usr/bin/python3


from argparse import ArgumentParser
from functools import partial
from tcpmitm.algs import packet_transform_and_forward_loop
from tcpmitm.connector import Connector, make_connector_args
from tcpmitm.sloppiness import make_sloppy_args
from tcpmitm.utils import add_all_args


def server_routine(server_conn):
    with server_conn as conn:
        while True:
            data = conn.recv(1500)
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


if __name__ == "__main__":
    parser = ArgumentParser(description="Brief example of tcp mitm usage")
    args, _, check_and_break = add_all_args(parser,
                                            make_connector_args,
                                            make_sloppy_args)

    server_port, middle_port = args.server_port, args.middle_port
    msgs = ["aaaaaaa", "aaaa", "exit"]

    connector = Connector(server_port, middle_port)
    connector.connect(
        partial(server_routine, server_conn=connector.server),
        partial(packet_transform_and_forward_loop,
                mitm=connector.mitm,
                transform=check_and_break),
        partial(client_routine, client_conn=connector.client, msgs=msgs)
    )
