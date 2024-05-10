# Port Scanner

- Authors: Sophia Dai, Nayeon Shin

## List of all files included in the project

```
.
├── src
│   └── port_scanner.py
├── Pipfile
├── Pipfile.lock
└── README.md
```

## Instructions on how to run the project

```bash
$ pipenv shell
$ pipenv install
$ cd src
# Example
$ python3 port_scanner.py glasgow.smith.edu -mode connect -order random -ports known
```

## Significant challenges and their solutions

The coding aspect of our project was not challenging. However, testing was more complex. We utilized nmap to verify whether our code yielded identical results, but there were discrepancies such as several missing ports that appeared in nmap’s output but not in ours.
For TCP connect scan, we initially used both `scapy.sr1` and `socket` to verify if ports were open, inadvertently filtering out some ports. But simplifying the process to only use `socket.connect` for scanning aligned our results with those of nmap.
Regarding TCP SYN scan, we could not figure out why 53 is shown as open in our program, while Nmap sees it closed. Also, we couldn't find a way to correlate the RST packet sent in response to the SYN/ACK packet from the server.

## Each person's specific contributions to the project

- Sophia:
  - `tcp_connect()`
  - `udp_scan()`
  - Getting `argparse` options
- Nayeon:
  - `tcp_syn_scan()`
  - Processing `argparse` options
  - `check_is_alive_host()`

## Further improvements

Since we were running out of time, we prioritized the functionality of our code to other aspects such as readability, reusability, and maintability. Hence, the code is not clean.
