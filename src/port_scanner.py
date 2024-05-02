from scapy.all import ICMP, IP, TCP, send, sr1
import random
import socket
import argparse
import sys 


def check_is_alive_host(target_host: str) -> bool:
    icmp_echo_request = IP(dst=target_host) / ICMP()
    icmp_echo_reply = sr1(icmp_echo_request, timeout=1, verbose=0)
    return bool(icmp_echo_reply)


def tcp_connect_scan(host, port):
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
                        return [True, data]
                except ConnectionRefusedError:
                    print("error")
        return [False, 0]


def tcp_syn_scan(target_host: str, ports: list[int]) -> list[tuple[int, str]]:
    def check_is_open_port(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((target_host, port))
            except (socket.error, OSError):
                return False

        return True

    def get_service_name(port: int) -> str:
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "unknown"

        return service

    open_ports = []

    for port in ports:
        is_open_port = check_is_open_port(port)
        if not is_open_port:
            continue

        syn_packet = IP(dst=target_host) / TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=1, verbose=0)

        if response:
            is_syn_ack = response.haslayer(TCP) and response.getlayer(TCP).flags & 0x12

            if is_syn_ack:
                service = get_service_name(port)
                open_ports.append((port, service))

                rst_packet = IP(dst=target_host) / TCP(dport=port, flags="R")
                send(rst_packet)

    return open_ports

def udp_scan(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, port))
        s.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
        s.settimeout(3)
        return True
    except socket.timeout:
        return False
    except ConnectionRefusedError:
        return False
    return False

def get_open_ports(target: str, mode: str, order: str, ports: str):
    open_ports = []
    banners={}
    if ports == 'all':
        ports_range = list(range(1, 65535))
    elif ports == 'known':
        ports_range = list(range(1, 1023))
    for port in ports_range:
        if mode == 'connect':
            if tcp_connect_scan(target, port)[0]:
                open_ports.append(port)
                banners[port] = (tcp_connect_scan(target, port)[1])
        if mode == 'udp':
            if udp_scan(target, port):
                open_ports.append(port)
    return open_ports


def scan_ports(target_host: str, mode: str, order: str, ports: str) -> list:
    # TODO: return type hint
    # TODO: group params (too many params)
    # TODO: input validation
    ALL_PORT_COUNT = 65536
    KNOWN_PORT_COUNT = 1024

    modes_to_functions = {
        "connect": None,  # TODO
        "syn": tcp_syn_scan,
        "udp": None  # TODO
    }
    scan = modes_to_functions.get(mode)

    if not scan:
        # TODO: capitalize
        raise NotImplementedError(f"{mode} scan is not implemented yet.")

    port_count = ALL_PORT_COUNT if ports == "all" else KNOWN_PORT_COUNT
    ports_to_scan = list(range(port_count))

    if order == "random":
        random.suffle(ports_to_scan)

    open_ports = scan(target_host, ports_to_scan)
    return open_ports


def main():
    #Usage example: python3 port_scanner.py glasgow.smith.edu -mode connect -order random -ports known
    #parse information from the command
    parser = argparse.ArgumentParser()
    parser.add_argument('target', type=str, help='Target IP address')
    parser.add_argument('-mode', type=str, choices=['connect', 'syn', 'udp'], default='connect',
                        help='Scanning mode[connect/syn/udp](default=connect)')
    parser.add_argument('-order', type=str, choices=['order','random'], default='order',
                        help='Order of Ports Scanning[order/random](default=order)')
    parser.add_argument('-ports', type=str, choices=['all', 'known'], default='all',
                        help='Scan Ports Range[all/known](default=all)')
    args = parser.parse_args()
    target = args.target
    mode = args.mode
    order = args.order
    ports = args.ports
    #Convert target to IP address
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

if __name__ == "__main__":
    main()
