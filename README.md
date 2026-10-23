# PYNMAP

A simple, multithreaded TCP port scanner written in Python using Scapy. PYNMAP performs TCP SYN scans against a target host, classifies each port as **OPEN**, **CLOSED**, or **FILTERED**, and resolves the common service name associated with each port.

```
------------------------------------------------------------
[+] PORT 80 > HTTP : OPEN
[-] PORT 23 > TELNET : CLOSED
[*] PORT 445 > MICROSOFT-DS : FILTERED
------------------------------------------------------------
```

## Features

- TCP SYN scanning (half-open scan) using raw packets via Scapy
- Multithreaded scanning for faster results
- Automatic service name resolution based on port number
- Color-coded terminal output (green = open, yellow = filtered, red = closed)
- Simple CLI powered by `argparse`
- Input validation for both target IP address and port list

## Requirements

- Python 3.10+
- [Scapy](https://scapy.net/)
- [colorama](https://pypi.org/project/colorama/)

Install the dependencies with pip:

```bash
pip install scapy colorama
```

> **Note:** Scapy requires administrator/root privileges to craft and send raw packets.

## Usage

```bash
sudo python pynmap.py <target> [-p PORTS] [-t THREADS]
```

### Arguments

| Argument          | Description                                              | Default                |
| ----------------- | --------------------------------------------------------- | ----------------------- |
| `target`          | Target IP address to scan                                 | required                |
| `-p`, `--ports`   | Comma-separated list of ports to scan                      | `21,22,23,80,443,445`   |
| `-t`, `--threads` | Number of threads used to scan ports concurrently          | `1`                      |

### Examples

Scan the default ports on a target:

```bash
sudo python pynmap.py 192.168.1.1
```

Scan specific ports:

```bash
sudo python pynmap.py 192.168.1.1 -p 22,80,443,8080
```

Scan with multiple threads for faster results:

```bash
sudo python pynmap.py 192.168.1.1 -p 1,22,80,443,3306,8080 -t 10
```

## How It Works

1. The target IP address and port list are validated before scanning starts.
2. All ports are placed into a thread-safe queue.
3. A pool of worker threads pulls ports from the queue and performs a TCP SYN scan on each one:
   - If a `SYN-ACK` is received, the port is marked **OPEN** and a `RST` packet is sent to close the connection gracefully.
   - If a `RST` is received, the port is marked **CLOSED**.
   - If no response is received within the timeout, the port is marked **FILTERED**.
4. Results are printed to the terminal in real time, color-coded by status.

## Disclaimer

This tool is intended for educational purposes and for scanning networks and systems you own or have explicit permission to test. Unauthorized port scanning may be illegal in your jurisdiction. Use responsibly.

## Author

Created by [thiagosantosjrdev](https://github.com/thiagosantosjrdev)

## License

This project is licensed under the MIT License.
