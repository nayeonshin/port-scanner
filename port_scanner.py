from scapy.all import ICMP, IP, sr1


def check_is_alive_host(target: str) -> bool:
    icmp_echo_request = IP(dst=target) / ICMP()
    icmp_echo_reply = sr1(icmp_echo_request, timeout=1, verbose=0)
    return bool(icmp_echo_reply)


def main():
    pass


if __name__ == "__main__":
    main()
