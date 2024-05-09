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

def tcp_connect(host: str, ports: list[int]) -> (list, dict):
    def tcp_connect_if_open(host, port) -> [bool, dict]:
        #Create a socket object with a timeout of 0.2 seconds
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            # Attempt to connect to the target port
            s.connect((host, port))
            s.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            banner = s.recv(1024)
            s.close()
            if banner:
                # If banner information is received, return True and the banner
                data = banner.decode().strip()
                return [True, data]
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            if isinstance(e, socket.timeout):
                pass
            elif isinstance(e, ConnectionRefusedError):
                pass
            elif isinstance(e, OSError) and e.errno == 49:
                pass
            else:
                pass
        # Return False and None if port is closed or unreachable
        return [False, None]

    # Initialize lists to store open ports and banners
    open_ports = []
    banners = {}

    for port in ports:
        # Check if the port is open and retrieve banner information if available
        if tcp_connect_if_open(host, port) != None:
            if tcp_connect_if_open(host, port)[0] == True:
                open_ports.append(port)
                banners[port] = (tcp_connect_if_open(host, port)[1])
    return open_ports, banners


def tcp_syn_scan(target_host: str, ports: list[int]) -> list[int, str]:
    open_ports = []

    for port in ports:
        # Send a SYN packet to the port and wait for a response, timeout=0.2
        syn_packet = IP(dst=target_host) / TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=0.2, verbose=0)
        # Check for response
        if response:
            is_syn_ack = response.haslayer(TCP) and response.getlayer(TCP).flags & 0x12

            if is_syn_ack:
                open_ports.append(port)

                rst_packet = IP(dst=target_host) / TCP(dport=port, flags="R")
                send(rst_packet, verbose=0)

    return open_ports


def udp_scan(host: str, ports: list[int]) -> list[int]:
    def if_port_close(host: str, port: int) -> bool:
        # Send a UDP packet to the port and wait for a response, timeout=0.2
        udp_packet = sr1(IP(dst=host) / UDP(sport=port, dport=port), timeout=0.2, verbose=0)
        if udp_packet == None:
            return False
        else:
            # If an ICMP packet with code 3 (Port Unreachable) is received, the port is closed
            if udp_packet.haslayer(ICMP) and int(udp_packet.getlayer(ICMP).code) == 3:
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
    KNOWN_PORT_COUNT = 1024

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
        raise NotImplementedError(f"{mode} scan is not implemented yet.")

    port_count = ALL_PORT_COUNT if ports == "all" else KNOWN_PORT_COUNT
    ports_to_scan = list(range(port_count))

    if order == "random":
        random.shuffle(ports_to_scan)

    open_ports = scan(target_ip, ports_to_scan)
    if mode == "connect":
        print(f"Not shown: {port_count - len(open_ports[0])} closed ports")
        print("PORT     STATE SERVICE")
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
        print("PORT     STATE SERVICE")
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
        print("PORT     STATE SERVICE")
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
