from scapy.all import ICMP, IP, TCP, send, sr1
import random
import socket
import sys  # TODO: use argparse


def check_is_alive_host(target_host: str) -> bool:
    icmp_echo_request = IP(dst=target_host)/ICMP()
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
                        return data
                except ConnectionRefusedError:
                    print("error")
        return False
    
    # Question - why do we return False in the end?
    # TODO: params - target_host & ports


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
        
        syn_packet = IP(dst=target_host)/TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=1, verbose=0)

        if response:
            is_syn_ack = response.haslayer(TCP) and response.getlayer(TCP).flags & 0x12
            
            if is_syn_ack:
                service = get_service_name(port)
                open_ports.append((port, service))

                rst_packet = IP(dst=target_host)/TCP(dport=port, flags="R")
                send(rst_packet)
    
    return open_ports


def udp_scan(host, port):
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
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.connect((host, port))
                    s.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                    s.settimeout(5)
                    banner = s.recv(1024)
                    print("Port {port} is open")
                    s.close()
                    if banner:
                        data = banner.decode().strip()
                        print(data)
                        return data
                except socket.timeout:
                    print("Port {port} is filtered")
                except ConnectionRefusedError:
                    print("Port {port} is closed")
            return False


def scan_ports(target_host: str, mode: str, order: str, ports: str) -> None:
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

    scan(target_host, ports_to_scan)


def main():
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


if __name__ == "__main__":
    main()
