from functools import partial


def packet_transform_and_forward_loop(mitm, transform):
    recv_timeout_in_forwarding = mitm._BLOCKING_TIMEOUT
    recvs_select = utils.select_from_functions(
        ("client", partial(mitm.recv_from_client, timeout=recv_timeout_in_forwarding)),
        ("server", partial(mitm.recv_from_server, timeout=recv_timeout_in_forwarding)),
    )

    no_messages = {"client": False, "server": False}

    while True:
        src, res = next(recvs_select)

        if isinstance(res, NoMessages):
            no_messages[src] = True
            if sum(no_messages.values()) == len(no_messages):
                break
        no_messages[src] = False 

        if isinstance(res, RecvRoutineStopped):
            break

        new_pkt = transform(res)

        # TODO: change to good checking!
        if src == "client":
            mitm.send_to_server(new_pkt)
        elif src == "server":
            mitm.send_to_client(new_pkt)
