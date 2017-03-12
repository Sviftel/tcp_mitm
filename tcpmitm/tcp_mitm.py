import scapy.all
import socket
import subprocess as subpr
from queue import Empty, Queue
from contextlib import contextmanager
from threading import Thread


# XXX avoid using of a name more then once.
# Reader can easily miss that there were 2 different
# objects with the same name and threat them as one.
# precise names help to reduce duplicate names counts.

# XXX please use more explicit coding.
# Create class called like RecvLoopThread
# with its __enter__ and __exit__ functions.
# All this 'magic' shorcuts (syntactic shugars) usually
# introduce problems with readability.
@contextmanager
def run_recv(mitm):
    tr = Thread(name="mitm_recv", target=mitm.recv_routine)
    tr.start()
    try:
        yield
    finally:
        mitm.run_recv = False
        tr.join()
        mitm.close()


class TcpMitmException(Exception):
    pass


class RecvRoutineStopped(TcpMitmException):
    def __str__(self):
        return "Receive routine has been stopped"


class NoMessages(TcpMitmException):
    def __init__(self, src):
        self._src = src

    def __str__(self):
        return "No messages received from {}".format(self._src)


class TcpMitm:
    def __init__(self, server_port, middle_port):
        self._BLOCKING_TIMEOUT = 2.0
        self._TRG_ADDR = ("127.0.0.1", 0)
        self._buf_size = 65536

        self.sock = socket.socket(socket.AF_INET,
                                  socket.SOCK_RAW,
                                  socket.IPPROTO_TCP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.sock.settimeout(self._BLOCKING_TIMEOUT)

        self.server_port, self.client_port = server_port, 0
        self.middle_port = middle_port

        self._client_recv_q, self._server_recv_q = Queue(), Queue()

    def close(self):
        self.sock.close()

    def _recv_from_q(self, block, timeout, *, queue):
        if not block:
            if not self._running_recv:
                raise RecvRoutineStopped
            pkt = queue.get_nowait()
            queue.task_done()
            return pkt

        timeout_was_not_set = timeout is None
        if timeout_was_not_set:
            timeout = self._BLOCKING_TIMEOUT

        # XXX when self._running_recv == False, queue still can contain
        # packets. Is it ok?
        while self._running_recv:
            try:
                pkt = queue.get(timeout=timeout)
            except Empty:
                if timeout_was_not_set:
                    continue
                if not self._running_recv:
                    raise RecvRoutineStopped
                raise Empty

            queue.task_done()
            return pkt
        raise RecvRoutineStopped

    def recv_from_client(self, block=True, timeout=None):
        try:
            return self._recv_from_q(block, timeout, queue=self._client_recv_q)
        except Empty:
            raise NoMessages("client")

    def recv_from_server(self, block=True, timeout=None):
        try:
            return self._recv_from_q(block, timeout, queue=self._server_recv_q)
        except Empty:
            raise NoMessages("server")

    # XXX this should be private method _recv_routine
    # place all private methods in the end of the class
    # XXX be more precise. It helps to read the code
    # and helps to limit responsibilities of classes/
    # vars/methods/...
    # recv_routine -> sock_recv_loop
    # run_recv -> run_sock_recv_loop
    def recv_routine(self):
        self.run_recv, self._running_recv = True, True

        while self.run_recv:
            try:
                data, addr = self.sock.recvfrom(self._buf_size)
            except socket.timeout:
                continue

            # XXX read packet size from ip/tcp header and check that it
            # suites into the buffer well
            if addr != self._TRG_ADDR or not data:
                continue

            ip_pkt = scapy.all.IP(data)
            if "IP" not in ip_pkt or "TCP" not in ip_pkt["IP"]:
                continue
            tcp_pkt = ip_pkt["TCP"]

            # if client's port is still unknown
            if not self.client_port:
                # and incoming packet is SYN, goes to server
                if tcp_pkt.flags == 2 and tcp_pkt.dport == self.middle_port:
                    self.client_port = tcp_pkt.sport

            sport, dport = tcp_pkt.sport, tcp_pkt.dport

            if sport == self.client_port and dport == self.middle_port:
                self._client_recv_q.put(ip_pkt)
                continue

            if sport == self.server_port and dport == self.middle_port:
                self._server_recv_q.put(ip_pkt)
                continue

        #XXX thread-shared variables should be protected using lock
        # or atomic operation
        self._running_recv = False

    def send_to_client(self, pkt):
        pkt.setfieldval("dport", self.client_port)
        pkt.setfieldval("sport", self.middle_port)

        del pkt['IP'].chksum, pkt['TCP'].chksum
        raw_pkt = bytes(pkt)
        self.sock.sendto(raw_pkt, self._TRG_ADDR)

    def send_to_server(self, pkt):
        pkt.setfieldval("dport", self.server_port)
        pkt.setfieldval("sport", self.middle_port)

        del pkt['IP'].chksum, pkt['TCP'].chksum
        raw_pkt = bytes(pkt)
        self.sock.sendto(raw_pkt, self._TRG_ADDR)
