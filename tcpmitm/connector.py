import socket
from threading import Thread

import .utils
from .tcp_mitm import NoMessages, RecvRoutineStopped, TcpMitm, run_recv


def make_connector_args(parser):
    group = parser.add_argument_group("connection")

    middle_port_help = "client and server will be sending their messages here"
    middle_port_help += " (I hope you set up dropping RSTs)"
    group.add_argument("--middle_port", type=int, help=middle_port_help,
                       required=True)
    group.add_argument("--server_port", type=int, help="server port",
                       required=True)

    parsed_args = yield

    assert_msg = "Server must be listening not on the middle port!"
    assert parsed_args.middle_port != parsed_args.server_port, assert_msg


# XXX Bad naming, not clear responsibility.
# You already have Client and Server classes
# that can be self-contained. Add a thread into them
# and that's all.
# Do the same for mitm MitmRecvLoopThread.
# XXX We need to discuss resource management in the app (threads, files, shared vars, ...).
# Now I see that you easily move resources around the code - this makes it complicated.
class Connector:
    def __init__(self, server_port, middle_port):
        self.server = Server(server_port, utils.LockedValue(False))
        self.client = Client(middle_port)
        self.mitm = TcpMitm(server_port, middle_port)

    def connect(self, server_routine, fwd_routine, client_routine):
        thr_server = Thread(name="server", target=server_routine)
        thr_fwd = Thread(name="pkt_fwd", target=fwd_routine)
        thr_client = Thread(name="client", target=client_routine)

        with run_recv(self.mitm):
            thr_server.start()
            while not self.server._start_flag:
                pass

            thr_fwd.start()
            thr_client.start()

            thr_server.join()
            thr_client.join()

            # TODO: wait for forwarder to end right here!

        thr_fwd.join()
        print("Mitm connection closed")

# XXX make all not exported classes private for this module.
# (add _ as name prefix)
class Server:
    def __init__(self, port, start_flag):
        self._port = port
        self._start_flag = start_flag

        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", port))

    def __enter__(self):
        self._start_flag.set(True), self._sock.listen(1)
        conn, addr = self._sock.accept()

        self.conn = conn
        return self.conn

    def __exit__(self, *exc_info):
        self.conn.close(), self._sock.close()
        print("Server finished")


class Client:
    def __init__(self, server_port):
        self._server_port = server_port
        self.sock = socket.socket()
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def __enter__(self):
        self.sock.connect(("127.0.0.1", self._server_port))
        return self.sock

    def __exit__(self, *exc_info):
        self.sock.close()
        print("Client finished")
