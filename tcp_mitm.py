import scapy.all
import socket
import subprocess as subpr
from queue import Empty, Queue
from contextlib import contextmanager
from threading import Thread


@contextmanager
def RunMitm(server_port, middle_port):
    mitm = TcpMitm(server_port, middle_port)
    tr = Thread(name="mitm_recv", target=mitm.recv_routine)
    tr.start()

    try:
        yield mitm
    finally:
        mitm.run_recv = False
        tr.join()
        mitm.close()


class TcpMitmException(Exception):
    pass


class RecvRoutineStopped(TcpMitmException):
    def __str__(self):
        return "Receive routine has been stopped"
        


TRG_ADDR = ("127.0.0.1", 0)
BLOCKING_TIMEOUT = 2.0

# TODO: split recv to _to_client, _to_server
class TcpMitm:
    def __init__(self, server_port, middle_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.sock.settimeout(BLOCKING_TIMEOUT)

        self.server_port, self.client_port = server_port, 0
        self.middle_port = middle_port

        self._recv_q = Queue()
        # self._client_q, self._server_q = Queue(), Queue()

    def close(self):
        self.sock.close()

    def recv_from_queue(self):
        while self._running_recv:
            try:
                pkt = self._recv_q.get(timeout=BLOCKING_TIMEOUT)
            except Empty:
                continue
            self._recv_q.task_done()
            return pkt
        raise RecvRoutineStopped

    def recv_routine(self):
        self.run_recv, self._running_recv = True, True

        while self.run_recv:
            try:
                data, addr = self.sock.recvfrom(1500)
            except socket.timeout:
                continue

            if addr != TRG_ADDR or not data:
                continue

            ip_pkt = scapy.all.IP(data)
            if "IP" not in ip_pkt or "TCP" not in ip_pkt["IP"]:
                continue
            tcp_pkt = ip_pkt["TCP"]

            # if client's port is still unknown and incoming packet "goes from him"
            if not self.client_port and tcp_pkt.flags == 2 and tcp_pkt.dport == self.middle_port:
                self.client_port = tcp_pkt.sport

            known_host = tcp_pkt.sport == self.client_port or tcp_pkt.sport == self.server_port
            if tcp_pkt.dport != self.middle_port or not known_host:
                continue

            # source_is_client = tcp_pkt.sport == self.client_port
            # if source_is_client:
            #     self._client_q.put(ip_pkt)
            # else:
            #     self._server_q.put(ip_pkt)

            self._recv_q.put(ip_pkt)
        self._running_recv = False

    def send_to_client(self, pkt):
        pkt.setfieldval("dport", self.client_port)
        pkt.setfieldval("sport", self.middle_port)

        del pkt['IP'].chksum, pkt['TCP'].chksum
        raw_pkt = bytes(pkt)
        self.sock.sendto(raw_pkt, TRG_ADDR)

    def send_to_server(self, pkt):
        pkt.setfieldval("dport", self.server_port)
        pkt.setfieldval("sport", self.middle_port)

        del pkt['IP'].chksum, pkt['TCP'].chksum
        raw_pkt = bytes(pkt)
        self.sock.sendto(raw_pkt, TRG_ADDR)
