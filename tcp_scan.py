import sys
import scapy
from scapy.all import *
from scapy.all import ICMP, IP, TCP, send, sr1
import socket
if len(sys.argv) < 3:
    print("Usage: python3 port_scanner.py [-options] target")
    sys.exit(1)

options = sys.argv[1]
target = sys.argv[-1]

try:
    ip_address = socket.gethostbyname(target)
except socket.gaierror:
    print("Error: Target is not a valid hostname or IP address.")
    sys.exit(1)

if not target.replace('.', '').isdigit():
    try:
        ip_address = socket.gethostbyname(target)
        print(ip_address)
    except socket.gaierror:
        print("Error: Target is not a valid hostname or IP address.")
        sys.exit(1)
else:
    target_ip = target

def tcp_connect(host, port):
    ip_packet = IP(dst = host)
    tcp_packet = TCP(dport = port, flags="S")
    final_packet = ip_packet/tcp_packet
    response = sr1(final_packet, timeout=5)

    if response is not None:
        if response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:
                new_tcp_packet = TCP(sport=response.dport, dport=response.sport, flags="R")
                new_packet = ip_packet/new_tcp_packet
                send(new_packet, verbose=0)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.connect((host, port))
                    s.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                    banner = s.recv(1024)
                    print("Port {port} is open")
                    s.close()
                    if banner:
                        data = banner.decode().strip()
                        print(data)
                        return data
                except ConnectionRefusedError:
                    print("error")
        return False

def udp_scan()



if __name__ == '__main__':
    tcp_connect(target, 80)







