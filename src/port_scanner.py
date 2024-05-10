import argparse
import random
import socket
import sys
import time
from dataclasses import dataclass
from datetime import datetime

from scapy.all import ICMP, IP, TCP, UDP, send, sr1


@dataclass
class ScanConfig:
    target_ip_address: str
    mode: str
    order: str
    ports: str


def resolve_target(target: str) -> str | None:
    """
    Resolve a hostname to an IP address.

    Args:
        target (str): The target hostname to resolve.

    Returns:
        str | None: The resolved IP address or None if resolution fails.
    """
    try:
        target_ip_address = socket.gethostbyname(target)
        return target_ip_address
    except socket.gaierror:
        print("Error: Target is not a valid hostname or IP address.")
        sys.exit(1)


def check_is_alive_host(target_host: str) -> bool:
    """
    Check if a host is alive by sending an ICMP echo request.

    Args:
        target_host (str): IP address or hostname of the target.

    Returns:
        bool: True if the host responds to the ping, False otherwise.
    """
    icmp_echo_request = IP(dst=target_host) / ICMP()
    icmp_echo_reply = sr1(icmp_echo_request, timeout=0.2, verbose=0)
    return bool(icmp_echo_reply)


def get_service_name(port: int) -> str:
    """
    Retrieve the service name associated with a given port number.

    Args:
        port (int): The port number.

    Returns:
        str: The service name if known, otherwise 'unknown'.
    """
    try:
        service = socket.getservbyport(port)
    except OSError:
        service = "unknown"

    return service


def print_messages(target_host: str) -> None:
    """
    Print initial messages for a port scanning session.

    Args:
        target_host (str): The target IP address.
    """
    LINE_WIDTH = 100

    current_time = str(datetime.now())
    message = "Starting port scan"
    padding_width = LINE_WIDTH - (len(message) + len(current_time))

    print(f"{message:<{padding_width}} at {current_time}")
    print(f"Interesting ports on {target_host}")


def tcp_connect_scan(target_host: str, ports: list[int]) -> tuple[list, dict]:
    """
    Perform a TCP connect scan on a list of ports.

    Args:
        target_host (str): The target IP address.
        ports (list[int]): A list of ports to scan.

    Returns:
        tuple[list, dict]: A tuple containing a list of open ports and a dictionary of banners.
    """

    def check_is_open_port(port) -> tuple[bool, dict | None]:
        # Create a socket object with a timeout of 0.2 seconds.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)

        try:
            # Attempt to connect to the target port.
            s.connect((target_host, port))
            s.send(b"GET / HTTP/1.1\r\nHost: " + target_host.encode() + b"\r\n\r\n")
            banner = s.recv(1024)
            s.close()

            if banner:
                # If banner information is received, return True and the banner.
                data = banner.decode().strip()
                return True, data
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            pass

        # Return False and None if port is closed or unreachable.
        return False, None

    # Initialize lists to store open ports and banners.
    open_ports = []
    banners = {}

    for port in ports:
        # Check if the port is open and retrieve banner information if available.
        is_open_port, banner = check_is_open_port(port)
        if is_open_port:
            open_ports.append(port)
            banners[port] = banner

    return open_ports, banners


def tcp_syn_scan(target_host: str, ports: list[int]) -> list[int]:
    """
    Perform a TCP SYN scan on a list of ports.

    Args:
        target_host (str): The target IP address.
        ports (list[int]): A list of ports to scan.

    Returns:
        list[int]: A list of ports where a SYN/ACK was received.
    """
    open_ports = []

    for port in ports:
        # Send a SYN packet to the port and wait for a response, timeout=0.2.
        syn_packet = IP(dst=target_host) / TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=0.2, verbose=0)

        # Check for response.
        if response:
            is_syn_ack = response.haslayer(TCP) and response.getlayer(TCP).flags & 0x12

            if is_syn_ack:
                open_ports.append(port)

                rst_packet = IP(dst=target_host) / TCP(dport=port, flags="R")
                send(rst_packet, verbose=0)

    return open_ports


def udp_scan(target_host: str, ports: list[int]) -> list[int]:
    """
    Perform a UDP scan on a list of ports.

    Args:
        target_host (str): The target IP address.
        ports (list[int]): A list of ports to scan.

    Returns:
        list[int]: A list of ports that are likely to be closed.
    """

    def check_is_closed(port: int) -> bool:
        # Send a UDP packet to the port and wait for a response, timeout=0.2.
        udp_packet = IP(dst=target_host) / UDP(sport=port, dport=port)
        response = sr1(udp_packet, timeout=0.2, verbose=0)
        if not response:
            return False

        # If an ICMP packet with code 3 (Port Unreachable) is received, the port is closed.
        is_closed = response.haslayer(ICMP) and int(response.getlayer(ICMP).code) == 3
        return is_closed

    closed_ports = []

    for port in ports:
        if check_is_closed(port):
            closed_ports.append(port)

    return closed_ports


def scan_ports(config: ScanConfig) -> tuple[int, list]:
    """
    Conduct a port scan based on the configurations.

    Args:
        config (ScanConfig): A dataclass containing all configurations for the scan.

    Returns:
        tuple[int, list]: Total number of ports and a list of open or closed ports.
    """
    ALL_PORT_COUNT = 65536
    KNOWN_PORT_COUNT = 1024

    # Unpack dataclass arguments.
    target_host = config.target_ip_address
    mode = config.mode
    order = config.order
    ports = config.ports

    # Get the function depending on the mode.
    modes_to_functions = {
        "connect": tcp_connect_scan,
        "syn": tcp_syn_scan,
        "udp": udp_scan,
    }
    scan = modes_to_functions.get(mode)
    if not scan:
        raise NotImplementedError(f"{mode} scan is not implemented yet.")

    print_messages(target_host)

    port_count = ALL_PORT_COUNT if ports == "all" else KNOWN_PORT_COUNT
    ports_to_scan = list(range(port_count))

    if order == "random":
        random.shuffle(ports_to_scan)

    # If UDP, these are closed ports. Otherwise, these are open ports.
    ports = scan(target_host, ports_to_scan)
    return port_count, ports


def print_ports(mode: str, port_count: int, ports: list | tuple[list, dict]) -> None:
    """
    Print the results of a port scan.

    Args:
        mode (str): The scanning mode used ('connect', 'syn', 'udp').
        port_count (int): The total number of ports that were considered for scanning.
        ports (list | tuple): A list of ports, or tuple of ports and banners.
    """

    def create_space(port_number: str) -> str:
        if port_number % 100 == port_number:
            return "   "
        elif port_number % 1000 == port_number:
            return "  "
        else:
            return " "

    match mode:
        case "connect":
            open_ports, banners = ports
            print(f"Not shown: {port_count - len(open_ports)} closed ports")
            print("Port     State Service")

            for port_number in open_ports:
                space = create_space(port_number)
                service_name = get_service_name(port_number)
                print(f"{port_number}/tcp{space}open{'  '}{service_name}{'   '}")
                print(f"banner:{banners[port_number]}")
        case "syn" | "udp":
            # Get the status and protocol based on the mode.
            if mode == "syn":
                status = "open"
                protocol = "tcp"
            else:
                status = "closed"
                protocol = mode

            for port_number in ports:
                space = create_space(port_number)
                service_name = get_service_name(port_number)
                print(
                    f"{port_number}/{protocol}{space}{status}{'  '}{service_name}{'   '}"
                )


def main():
    # Usage example: python3 port_scanner.py glasgow.smith.edu -mode connect -order random -ports known
    # Parse the command options.
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

    # Check the host reachability.
    target_ip_address = resolve_target(args.target)
    is_alive_host = check_is_alive_host(target_ip_address)
    if not is_alive_host:
        print("Target is not reachable.")
        sys.exit(1)

    start_time = time.time()

    # Scan ports.
    config = ScanConfig(
        target_ip_address=target_ip_address,
        mode=args.mode,
        order=args.order,
        ports=args.ports,
    )
    port_count, scanned_ports = scan_ports(config)
    print_ports(mode=args.mode, port_count=port_count, ports=scanned_ports)

    current_time = time.time()

    print(f"scan done! 1 IP address scanned in {current_time - start_time} seconds.")


if __name__ == "__main__":
    main()
