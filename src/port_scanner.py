from scapy.all import ICMP, IP, TCP, send, sr1
import random
import socket


def check_is_alive_host(target_host: str) -> bool:
    icmp_echo_request = IP(dst=target_host)/ICMP()
    icmp_echo_reply = sr1(icmp_echo_request, timeout=1, verbose=0)
    return bool(icmp_echo_reply)


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


def scan_ports(mode: str, order: str, ports: str) -> None:
    # TODO: input validation
    ALL_PORT_COUNT = 65536
    KNOWN_PORT_COUNT = 1024

    modes_to_functions = {
        "connect": None,  # TODO
        "syn": tcp_syn_scan,
        "udp": None
    }
    scan = modes_to_functions.get(mode)

    if not scan:
        raise NotImplementedError(f"{mode} scan is not implemented yet.")
    
    port_count = ALL_PORT_COUNT if ports == "all" else KNOWN_PORT_COUNT
    ports_to_scan = list(range(port_count))

    if order == "random":
        random.suffle(ports_to_scan)

    scan(None, ports_to_scan)  # TODO: target host


def main():
    pass


if __name__ == "__main__":
    main()
