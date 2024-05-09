import argparse
import random
import socket
import sys
import time
from datetime import datetime

from scapy.all import ICMP, IP, TCP, UDP, send, sr1


def check_is_alive_host(target_host: str) -> bool:
    icmp_echo_request = IP(dst=target_host) / ICMP()
    icmp_echo_reply = sr1(icmp_echo_request, timeout=1, verbose=0)
    return bool(icmp_echo_reply)


def get_service_name(port: int) -> str:
    try:
        service = socket.getservbyport(port)
    except OSError:
        service = "unknown"

    return service


def tcp_connect_scan(host: str, ports: list[int]) -> tuple[list, dict]:
    def scan(host, port) -> str | None:  # TODO: is banner a string?
        ip_packet = IP(dst=host)
        syn_packet = ip_packet / TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=5)

        if response:
            # TODO: make is_syn_ack a function?
            is_syn_ack = response.haslayer(TCP) and response.getlayer(TCP).flags & 0x12

            if is_syn_ack:
                rst_tcp_packet = TCP(
                    sport=response.dport, dport=response.sport, flags="R"
                )
                rst_packet = ip_packet / rst_tcp_packet
                send(rst_packet, verbose=0)

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.connect((host, port))
                    s.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                    banner = s.recv(1024)
                    print(f"Port {port} is open")
                    s.close()

                    if banner:
                        data = banner.decode().strip()
                        print(
                            data
                        )  # TODO: question - should we print this here or in main()?
                        return data  # TODO: initially, we had a boolean. was it to indicate whether banner existed?
                except ConnectionRefusedError:
                    print("error")

            return None
        # TODO: question - do we also return None if no response?

    open_ports = []
    banners = {}

    for port in ports:
        banner = scan(host, port)

        if banner:
            service = get_service_name(port)
            open_ports.append((port, service))
            banners[port] = banner

    return open_ports, banners


def tcp_syn_scan(target_host: str, ports: list[int]) -> list[tuple[int, str]]:
    open_ports = []

    for port in ports:
        syn_packet = IP(dst=target_host) / TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=1, verbose=0)

        if response:
            is_syn_ack = response.haslayer(TCP) and response.getlayer(TCP).flags & 0x12

            if is_syn_ack:
                service = get_service_name(port)  # TODO: decouple this out
                open_ports.append((port, service))

                # TODO: question - Is this necessary?
                rst_packet = IP(dst=target_host) / TCP(dport=port, flags="R")
                send(rst_packet)

    return open_ports


def udp_scan(host: str, ports: list[int]) -> list[tuple[int, str]]:
    def check_is_open_port(port: int) -> bool:
        udp_packet = sr1(
            IP(dst=host) / UDP(sport=port, dport=port), timeout=2, verbose=0
        )
        if udp_packet:
            return True

        if udp_packet.haslayer(ICMP):
            print(
                port, "Closed"
            )  # TODO: question - do we want to print here or in main()?
            return False
        elif udp_packet.haslayer(UDP):
            print(port, "Open / filtered")  # TODO: same q
            return True
        else:
            print(port, "Unknown")  # TODO: same q
            print(udp_packet.summary())
            return False

    open_ports = []

    for port in ports:
        if check_is_open_port(port):
            service = get_service_name(port)
            open_ports.append((port, service))

    return open_ports


def scan_ports(target_host: str, mode: str, order: str, ports: str) -> list:
    # TODO: return type hint
    # TODO: group params (too many params)
    # TODO: input validation
    ALL_PORT_COUNT = 65536
    KNOWN_PORT_COUNT = 23

    start_time = datetime.now()
    start = time.time()
    # TODO: can use automatic alignment somehow instead of manual one
    print(f"Staring port scan           at {start_time}")
    print(f"Interesting ports on {target_host}")

    modes_to_functions = {
        "connect": tcp_connect_scan,
        "syn": tcp_syn_scan,
        "udp": udp_scan,
    }
    scan = modes_to_functions.get(mode)

    if not scan:
        raise NotImplementedError(f"{mode} scan is not implemented yet.")

    port_count = ALL_PORT_COUNT if ports == "all" else KNOWN_PORT_COUNT
    ports_to_scan = list(range(port_count))

    if order == "random":
        random.shuffle(ports_to_scan)

    open_ports = scan(target_host, ports_to_scan)
    print(open_ports)  # TODO: print in main()
    # print(f"Not shown: {port_count - len(open_ports)} closed ports")
    # print("Port     State Service")
    # for port_tuple in open_ports:
    #     #print(port_tuple)
    #     if port_tuple[0] % 100 == port_tuple[0]:
    #         space = "   "
    #     elif port_tuple[0] % 1000 == port_tuple[0]:
    #         space = "  "
    #     else:
    #         space = " "

    # TODO: question - do we want to print here or in main()? Or in a different function?
    match mode:
        case "connect":
            # TODO: question - why len(open_ports[0])?
            print(f"Not shown: {port_count - len(open_ports[0])} closed ports")
            print("Port     State Service")  # TODO: automatic alignment

            # TODO: what is the modulo for?
            for port_number, service_name in open_ports[
                0
            ]:  # TODO: question - why open_ports[0]?
                if port_number % 100 == port_number:
                    space = "   "
                elif port_number % 1000 == port_number:
                    space = "  "
                else:
                    space = " "

                print(f"{port_number}/tcp{space}open{'  '}{service_name}{'   '}")
                print(
                    f"banner:{open_ports[1][port_number]}"
                )  # TODO: question - why open_ports[1]?
        case "syn" | "udp":
            for port_number, service_name in open_ports:
                print(f"{port_number}/{mode}{space}open{'  '}{service_name}{'   '}")

    print(
        f"scan done! {len(ports)} IP address scanned in {time.time() - start} seconds."
    )
    return open_ports

def resolve_target(target: str) -> str | None:
    try:
        target_ip_address = socket.gethostbyname(target)
        return target_ip_address
    except socket.gaierror as e:
        print(f"Error: Target is not a valid hostname or IP address.")
        sys.exit(1)

def main():
    # Usage example: python3 port_scanner.py glasgow.smith.edu -mode connect -order random -ports known
    # parse information from the command
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("target", type=str, help="Target IP address")
    parser.add_argument(
        "-mode",
        type=str,
        choices=["connect", "syn", "udp"],
        default="connect",
        help="Scanning mode [connect/syn/udp] (default: %(default)s)",
    )
    parser.add_argument(
        "-order",
        type=str,
        choices=["order", "random"],
        default="order",
        help="Order of port scanning [order/random] (default: %(default)s)",
    )
    parser.add_argument(
        "-ports",
        type=str,
        choices=["all", "known"],
        default="all",
        help="Scan Ports Range [all/known] (default: %(default)s)",
    )
    args = parser.parse_args()

    target = args.target
    mode = args.mode
    order = args.order
    ports = args.ports

    target_ip_address = resolve_target(target)
    scan_ports(target_ip_address, mode, order, ports)

if __name__ == "__main__":
    main()
