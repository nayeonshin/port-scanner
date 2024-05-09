# Port Scanner

* Authors: Sophia Dai, Nayeon Shin

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

## One significant challenge and solution
TODO

## Each person's specific contributions to the project
- Sophia:
  - `tcp_connect()`
  - `udp_scan()`
  - Getting `argparse` options
- Nayeon:
  - `tcp_syn_scan()`
  - Processing `argparse` options
  - `check_is_alive_host()`