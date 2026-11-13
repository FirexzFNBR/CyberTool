# CyberTool

**CyberTool** is a collection of four python-based cybersecurity utilities designed for learning, security testing, and everyday use in authorized environments.

The project brings together practical tools for password analysis, network scanning, file encryption, and basic web security checks.

## Tools

| Tool | Directory | Description |
|---|---|---|
| **Password Checker** | `passchecker/` | Evaluates password strength by analyzing entropy, character diversity, and common patterns. |
| **Port Scanner** | `portscan/` | Performs multithreaded TCP port scanning to identify open ports on authorized networks. |
| **Crypto Tool** | `crypto/` | Generates file hashes and supports file encryption and decryption using AES-256-GCM. |
| **Web Security Scanner** | `wvscan/` | Checks HTTP security headers, cookie configurations, and TLS certificate validity. |

## Legal Notice

CyberTool was developed for educational purposes and authorized security testing.

The **Port Scanner** and **Web Security Scanner** should only be used against systems you own or have explicit permission to test.

Scanning third-party networks or websites without authorization may violate applicable laws. In Brazil, unauthorized access to computer systems may fall under Law No. 12,737/2012 (Carolina Dieckmann Law), depending on the circumstances.

By using this project, you are responsible for ensuring that all tests are performed legally and with proper authorization.

## Getting Started

### Requirements

- Python 3.8 or later
- `cryptography`
- `requests`

### Installation

Clone the repository and install the required dependencies:

```bash
git clone https://github.com/FirexzFNBR/cybertool.git
cd cybertool
pip install -r requirements.txt
```

## Usage

Each tool can be executed independently from its own directory.

**1. Password Checker**

Analyze password strength:

```bash
python passchecker/passchecker.py
```

**2. Port Scanner**

Scan TCP ports on your own network:

```bash
python portscan/portscan.py --host 192.168.0.1 --ports 1-1024 --i-have-authorization
```

**3. Crypto Tool**

Calculate the SHA-256 hash of a file:

```bash
python crypto/crypto.py hash --file document.pdf --algo sha256
```

Encrypt a file using a password:

```bash
python crypto/crypto.py encrypt --file secret.txt --password "your-password"
```

**4. Web Security Scanner**

Check the security configuration of a website you own or are authorized to test:

```bash
python wvscan/wvscan.py --url https://example.com
```

## Project Goals

CyberTool was created to explore practical cybersecurity concepts through small, independent Python tools.

The main goals are to:

- Make common security checks easier to understand and perform.
- Explore networking, cryptography, and web security.
- Encourage responsible security testing.
- Keep the codebase modular and easy to extend.

## License

This project is released under the [MIT License](LICENSE).
