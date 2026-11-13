import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-alt", 27017: "MongoDB",
}

def parser(spec: str):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(ports)

def scanner(host: str, port: int, timeout: float):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                service = KNOWN_PORTS.get(port, "unknown")
                return port, True, service
    except socket.error:
        pass
    return port, False, None

def main():
    parser = argparse.ArgumentParser(
        description="TCP port scanner (authorized use only)."
    )
    parser.add_argument("--host", required=True, help="Target IP or hostname.")
    parser.add_argument("--ports", default="1-1024", help="Example: 1-1024 or 22,80,443")
    parser.add_argument("--timeout", type=float, default=0.5, help="Timeout per port (s).")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads.")
    parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="Confirms that you are authorized to scan the target.",
    )
    args = parser.parse_args()
    if not args.i_have_authorization:
        print(
            "Error: use --i-have-authorization to confirm that you are the "
            "owner of the network/host or have explicit permission to scan it."
        )
        sys.exit(1)
    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"Could not resolve host: {args.host}")
        sys.exit(1)
    ports = parser(args.ports)
    print(f"\nScanning {args.host} ({ip}) — {len(ports)} port(s)...\n")
    open_ports = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scanner, ip, p, args.timeout) for p in ports]
        for future in as_completed(futures):
            port, is_open, service = future.result()
            if is_open:
                open_ports.append((port, service))
    open_ports.sort()
    if open_ports:
        print("Open ports found:")
        for port, service in open_ports:
            print(f"  {port:>5}/tcp  open  {service}")
    else:
        print("No open ports found in the specified range.")

if __name__ == "__main__":
    main()