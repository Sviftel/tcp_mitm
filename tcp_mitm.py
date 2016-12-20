import scapy.all
import socket
import subprocess as subpr


TRG_ADDR = ("127.0.0.1", 0)

undefined = -1
follow_stream = 0
c2s = 1
s2c = 2

# TODO: split recv and send to _to_client, _to_server
class TcpMitm:
    def __init__(self, server_port, middle_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.server_port, self.client_port = server_port, 0
        self.middle_port = middle_port
        self.current_direction = undefined
        self._sent_pkts = set()

    def close(self):
        self.sock.close()

    def recv(self):
        while True:
            data, addr = self.sock.recvfrom(1500)
            if addr != TRG_ADDR or not data:
                continue

            if data in self._sent_pkts:
                self._sent_pkts.remove(data)
                continue

            ip_pkt = scapy.all.IP(data)
            if "IP" not in ip_pkt or "TCP" not in ip_pkt["IP"]:
                continue
            tcp_pkt = ip_pkt["TCP"]

            # if client's port is still unknown and incoming packet "goes from him"
            if not self.client_port and tcp_pkt.flags == 2 and tcp_pkt.dport == self.middle_port:
                self.client_port = tcp_pkt.sport

            pkt_from_known_host = tcp_pkt.sport == self.client_port or tcp_pkt.sport == self.server_port
            if tcp_pkt.dport != self.middle_port or not pkt_from_known_host:
                continue

            source_is_client = tcp_pkt.sport == self.client_port
            self.current_direction = c2s if source_is_client else s2c

            yield ip_pkt

    # TODO: remove direction
    def send(self, pkt, direction=follow_stream):
        follow = direction == follow_stream
        unable_to_follow_stream = self.current_direction == undefined and follow
        send_to_unknown_client = not self.client_port and direction == c2s

        if direction == c2s or follow and self.current_direction == c2s:
            pkt.setfieldval("dport", self.server_port)
            pkt.setfieldval("sport", self.middle_port)
        elif direction == s2c or follow and self.current_direction == s2c:
            pkt.setfieldval("dport", self.client_port)
            pkt.setfieldval("sport", self.middle_port)

        del pkt['IP'].chksum
        del pkt['TCP'].chksum

        raw_pkt = bytes(pkt)
        self._sent_pkts.add(raw_pkt)
        self.sock.sendto(raw_pkt, TRG_ADDR)
