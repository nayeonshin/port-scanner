from scapy.all import ICMP, IP, TCP, send, sr1, UDP
import random
import time
import socket
from datetime import datetime
import argparse
import sys


def check_is_alive_host(target_host: str) -> bool:
    icmp_echo_request = IP(dst=target_host) / ICMP()
    icmp_echo_reply = sr1(icmp_echo_request, timeout=1, verbose=0)
    return bool(icmp_echo_reply)

def tcp_connect(host: str, ports: list[int]):
    def tcp_connect_if_open(host, port) -> [bool, str]:
        final_packet = IP(dst=host) / TCP(dport=port, flags="S")
        response = sr1(final_packet, timeout=5)

        if response is not None:
            if response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:
                    new_packet = IP(dst=host) / TCP(sport=response.dport, dport=response.sport, flags="R")
                    send(new_packet, verbose=0)
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        s.connect((host, port))
                        s.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                        banner = s.recv(1024)
                        print(f"Port {port} is open")
                        s.close()
                        if banner:
                            data = banner.decode().strip()
                            print(data)
                            return [True, data]
                    except ConnectionRefusedError:
                        print("error")
            return [False, None]

    open_ports = []
    banners = {}

    for port in ports:
        if tcp_connect_if_open(host, port) != None:
            if tcp_connect_if_open(host, port)[0] == True:
                open_ports.append(port)
                banners[port] = (tcp_connect_if_open(host, port)[1])
    return open_ports, banners


def tcp_syn_scan(target_host: str, ports: list[int]) -> list[tuple[int, str]]:

    open_ports = []

    for port in ports:
        syn_packet = IP(dst=target_host) / TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=1, verbose=0)

        if response:
            is_syn_ack = response.haslayer(TCP) and response.getlayer(TCP).flags & 0x12

            if is_syn_ack:
                open_ports.append(port)

                rst_packet = IP(dst=target_host) / TCP(dport=port, flags="R")
                send(rst_packet)

    return open_ports


def udp_scan(host: str, ports: list[int]) -> list[tuple[int, str]]:
    def if_port_close(host: str, port: int) -> bool:
        udp_packet = sr1(IP(dst=host) / UDP(sport=port, dport=port), timeout=2, verbose=0)
        if udp_packet == None:
            return False
        else:
            if udp_packet.haslayer(ICMP) and int(udp_packet.getlayer(ICMP).code) == 3:
                print(port, "Closed")
                return True
            else:
                return False

    close_ports = []
    for port in ports:
        if if_port_close(host, port):
            close_ports.append(port)
    return close_ports


def main():
    # Usage example: python3 port_scanner.py glasgow.smith.edu -mode connect -order random -ports known
    # parse information from the command
    parser = argparse.ArgumentParser()
    parser.add_argument('target', type=str, help='Target IP address')
    parser.add_argument('-mode', type=str, choices=['connect', 'syn', 'udp'], default='connect',
                        help='Scanning mode[connect/syn/udp](default=connect)')
    parser.add_argument('-order', type=str, choices=['order', 'random'], default='order',
                        help='Order of Ports Scanning[order/random](default=order)')
    parser.add_argument('-ports', type=str, choices=['all', 'known'], default='all',
                        help='Scan Ports Range[all/known](default=all)')
    args = parser.parse_args()
    target = args.target
    mode = args.mode
    order = args.order
    ports = args.ports

    ip_address = None  # Initialize target_ip with None

    # Convert target to IP address
    try:
        ip_address = socket.gethostbyname(target)
        target_ip = ip_address  # Assign target_ip after resolving the hostname
    except socket.gaierror:
        print("Error: Target is not a valid hostname or IP address.")
        sys.exit(1)

    is_alive_host = check_is_alive_host(target_ip)
    if not is_alive_host:
        print("Target is not reachable.")
        sys.exit(1)

    start_time = datetime.now()
    start = time.time()
    print(f"Staring port scan           at {start_time}")
    print(f"Interesting ports on {target_ip}")
    ALL_PORT_COUNT = 65536
    KNOWN_PORT_COUNT = 100

    port_count = ALL_PORT_COUNT if ports == "all" else KNOWN_PORT_COUNT
    ports_to_scan = list(range(port_count))

    if order == "random":
        random.shuffle(ports_to_scan)

    modes_to_functions = {
        "connect": tcp_connect,
        "syn": tcp_syn_scan,
        "udp": udp_scan
    }
    scan = modes_to_functions.get(mode)

    if not scan:
        # TODO: capitalize
        raise NotImplementedError(f"{mode} scan is not implemented yet.")

    port_count = ALL_PORT_COUNT if ports == "all" else KNOWN_PORT_COUNT
    ports_to_scan = list(range(port_count))

    if order == "random":
        random.shuffle(ports_to_scan)

    open_ports = scan(target_ip, ports_to_scan)
    if mode == "connect":
        print(f"Not shown: {port_count - len(open_ports[0])} closed ports")
        print("Port     State Service")
        for port_n in open_ports[0]:
            if port_n % 100 == port_n:
                space = "   "
            elif port_n % 1000 == port_n:
                space = "  "
            else:
                space = " "

            print(f"{port_n}/tcp{space}open{'  '}{socket.getservbyport(port_n)}{'   '}")
            print(f"banner:{open_ports[1][port_n]}")
    if mode == "syn":
        print(f"Not shown: {port_count - len(open_ports)} closed ports")
        print("Port     State Service")
        for port_n in open_ports:
            if port_n % 100 == port_n:
                space = "   "
            elif port_n % 1000 == port_n:
                space = "  "
            else:
                space = " "
            print(f"{port_n}/tcp{space}open{'  '}{socket.getservbyport(port_n)}{'   '}")
    if mode =="udp":
        print(f"Not shown: {len(open_ports)} closed ports")
        print("Port     State Service")
        for port_n in open_ports:
            if port_n % 100 == port_n:
                space = "   "
            elif port_n % 1000 == port_n:
                space = "  "
            else:
                space = " "
            print(f"{port_n}/udp{space}closed{' '}{socket.getservbyport(port_n)}{'   '}")

    print(f"scan done! 1 IP address scanned in {time.time() - start} seconds.")

 


if __name__ == "__main__":
    main()

