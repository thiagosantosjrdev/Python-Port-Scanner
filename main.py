from scapy.all import Packet, RandShort, RandInt, IP, TCP, sr1, send
from colorama import init, Fore, Style
from ipaddress import ip_address
from socket import getservbyport
from typing import Literal
import threading
from queue import Queue
import argparse
import logging
import sys


logging.basicConfig(format="[%(levelname)s] : %(threadName)s > %(message)s")


scapy_lock = threading.Lock()
print_lock = threading.Lock()


def verify_addr(addr: str) -> str:
    try:
        ip_address(addr)
    except ValueError:
        logging.error("INVALID IP ADDRESS")
        sys.exit(1)


def sanitize_ports(raw_ports: str) -> list[int]:
    port_list: list[str] = raw_ports.split(",")
    try:
        return [int(port.strip()) for port in port_list]
    except ValueError:
        logging.error("INVALID PORT")
        sys.exit(1)


def alert(message: str, level: int = 0) -> None:
    with print_lock:
        if level == 0:
            print(
                f"{Fore.GREEN}{Style.BRIGHT}{message}{Style.NORMAL}{Fore.RESET}",
                flush=True,
            )
        elif level == 1:
            print(
                f"{Fore.YELLOW}{Style.BRIGHT}{message}{Style.NORMAL}{Fore.RESET}",
                flush=True,
            )
        elif level == 2:
            print(
                f"{Fore.RED}{Style.BRIGHT}{message}{Style.NORMAL}{Fore.RESET}",
                flush=True,
            )
        else:
            print(
                f"{Fore.LIGHTBLACK_EX}{Style.BRIGHT}{message}{Style.NORMAL}{Fore.RESET}",
                flush=True,
            )


def find_service_name(port: int, protocol: str = "tcp") -> str:
    try:
        service_name: str = getservbyport(port, protocol)
        return service_name.upper()
    except (OSError, OverflowError):
        return "UNKNOWN"


def test_port_connection(
    ipaddr: str, port: int
) -> Literal["OPEN", "CLOSED", "FILTERED"]:
    my_port: int = int(RandShort())
    pkt: Packet = IP(dst=ipaddr) / TCP(
        sport=my_port, dport=port, flags="S", seq=int(RandInt())
    )

    with scapy_lock:
        response: Packet | None = sr1(pkt, timeout=3, verbose=0)

        if response is None:
            return "FILTERED"

        if response.haslayer(TCP):
            flags = response.getlayer(TCP).flags
            if "S" in flags:
                send(
                    (
                        IP(dst=ipaddr)
                        / TCP(
                            sport=my_port,
                            dport=port,
                            flags="R",
                            seq=response.getlayer(TCP).ack,
                            ack=response.getlayer(TCP).seq + 1,
                        )
                    ),
                    verbose=0,
                )
                return "OPEN"
            elif "R" in flags:
                return "CLOSED"

    return "FILTERED"


def worker_scan(target: str, queue: Queue) -> None:
    while not queue.empty():
        try:
            port = queue.get_nowait()
        except:
            break

        status = test_port_connection(target, port)
        service = find_service_name(port)
        if status == "OPEN":
            level = 0
            signal = "+"
        elif status == "FILTERED":
            level = 1
            signal = "*"
        elif status == "CLOSED":
            level = 2
            signal = "-"

        alert(f"[{signal}] PORT {port} > {service} : {status}", level=level)
        queue.task_done()


def main(ports: list[int], target: str, threads: int) -> None:
    queue: Queue = Queue()
    for port in ports:
        queue.put(port)

    thread_list: list[threading.Thread] = []
    actual_threads = min(threads, len(ports))

    for i in range(actual_threads):
        t = threading.Thread(
            target=worker_scan, args=(target, queue), name=f"ScannerThread-{i+1}"
        )
        thread_list.append(t)

    for t in thread_list:
        t.start()

    for t in thread_list:
        t.join()


if __name__ == "__main__":
    print("-" * 60)
    init()
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="PYPSCAN | version 1.0",
        description="A simple python port scanner :D",
        epilog="Created by thiagosantosjrdev",
    )
    parser.add_argument(
        "target", type=str, help="Target host for testing port connectivity"
    )
    parser.add_argument(
        "-p", "--ports", type=str, help="Ports to scan", default="21,22,23,80,443,445"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=1, help="Number of threads to be used"
    )

    try:
        args = parser.parse_args()
        ports: list[int] = sanitize_ports(args.ports)
        verify_addr(args.target)
        main(ports, args.target, args.threads)
    except SystemExit:
        sys.exit(1)
    finally:
        print("-" * 60)
