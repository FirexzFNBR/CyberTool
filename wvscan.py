import argparse
import socket
import ssl
import sys
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None

HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS connections (protects against downgrade attacks).",
    "Content-Security-Policy": "Mitigates XSS and content injection.",
    "X-Content-Type-Options": "Prevents MIME sniffing (should be 'nosniff').",
    "X-Frame-Options": "Protects against clickjacking.",
    "Referrer-Policy": "Controls information leakage via the Referer header.",
    "Permissions-Policy": "Restricts browser API access (camera, geolocation, etc.).",
}

def headers(url: str):
    response = requests.get(url, timeout=10, allow_redirects=True)
    headers = response.headers

    print(f"\nHTTP status: {response.status_code}")
    print(f"Final URL (after redirects): {response.url}\n")

    print("=== Security Headers ===")
    for header, description in HEADERS.items():
        if header in headers:
            print(f"  [OK]     {header}: {headers[header]}")
        else:
            print(f"  [MISSING] {header} — {description}")

    server = headers.get("Server")
    if server:
        print(f"\n[INFO] Exposed server banner: '{server}' "
              f"(consider hiding the version to reduce fingerprinting).")

    return response

def cookies(response):
    if not response.cookies:
        return
    print("\n=== Cookies ===")
    for cookie in response.cookies:
        flags = []
        if not cookie.secure:
            flags.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie).lower():
            flags.append("possibly missing HttpOnly")
        status = ", ".join(flags) if flags else "OK"
        print(f"  {cookie.name}: {status}")

def tls(hostname: str, port: int = 443):
    print("\n=== TLS Certificate ===")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                not_after = cert.get("notAfter")
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.utcnow()).days

                print(f"  Issued by: {issuer.get('organizationName', 'unknown')}")
                print(f"  Expires on: {not_after} ({days_left} days left)")
                if days_left < 15:
                    print("  [WARNING] Certificate is about to expire!")
    except Exception as e:
        print(f"  Could not verify the TLS certificate: {e}")

def main():
    parser = argparse.ArgumentParser(description="Web security scanner (passive/educational).")
    parser.add_argument("--url", required=True, help="Target URL, e.g. https://example.com")
    args = parser.parse_args()
    if requests is None:
        sys.exit("Install the dependency: pip install requests")
    parsed = urlparse(args.url)
    if not parsed.scheme:
        sys.exit("Include the scheme in the URL, e.g. https://example.com")
    print(f"Analyzing {args.url} ...")
    response = headers(args.url)
    cookies(response)
    if parsed.scheme == "https":
        tls(parsed.hostname, parsed.port or 443)

if __name__ == "__main__":
    main()