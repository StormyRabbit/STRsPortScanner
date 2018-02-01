import socket
from contextlib import closing
from scapy.all import *
import os
# tries to import scapy, needed for extra types of port scanning.
scapyImport = True
try:
    from scapy.all import *
except:
    scapyImport = False


class PortScanner:
    """Port scanning class. does a "regualar" port scan for TCP.
        and if scapy and root does extra port scanning types.
        inspired by: 
            http://resources.infosecinstitute.com/port-scanning-using-scapy/
    """

    def __init__(self):
        self.result = {'tcp': {}, 'udp': {}}

    def check_port(self, address, port, mode):
        if mode == 'udp':
            self._udp_scan(address, port)
        if mode == 'tcp':
            self._tcp_scan(address, port)

    def _tcp_scan(self, address, port):
        # do a standard port check on adress and port.
        # if faled do a Stealth TCP scan and a ACK port scan.
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(2)
            if sock.connect_ex((address, port)) == 0:
                self._add_result(address, port, 'tcp')
            else:
                if scapyImport: # if scappy imported
                    if os.getuid() == 0: # if root
                        resp = sr1(IP(dst=address)/TCP(sport=20, dport=port, flags="S"), timeout=2, verbose=0)
                        if resp is None:
                            return
                        if resp.haslayer(TCP):
                            if resp.getlayer(TCP).flags == 0x12:
                                self._add_result(address, port, 'tcp')
                        else:
                            resp = sr1(IP(dst=address) / TCP(dport=port, flags="A"), timeout=2, verbose=0)
                            if resp.getlayer(TCP).window > 0:
                                self._add_result(address, port, 'tcp')

    def _add_result(self, address, port, mode):
        # add a found port to the result datastructure.
        self.result[mode][address]['open_ports'].append(str(port))
        self.result[mode][address]['open_ports'] = list(set(self.result[mode][address]['open_ports']))

    def _udp_scan(self, address, port):
        # udp scan using scapy framework.
        if scapyImport: # scapy imported
            if os.getuid() == 0: # IF ROOT
                resp = sr1(IP(dst=address) / UDP(dport=int(port)), timeout=2, verbose=0)
                if resp is None:
                    retry = []
                    for c in range(0,3):
                        retry.append(sr1(IP(dst=address) / UDP(dport=int(port)), timeout=2, verbose=0))
                    for item in retry:
                        if item:
                            self._udp_scan(address, port)
                elif resp.haslayer(UDP):
                    self._add_result(address, port, 'udp')

    def scan_address(self, address, port_low_end, port_high_end, mode):
        # starts the scanning process of the argument data.
        if address not in self.result[mode]:
            self.result[mode] = {address: {'open_ports': []}}

        for port in range(port_low_end, port_high_end + 1):
            self.check_port(address, port, mode)

