import argparse
import hashlib
import os
import sys
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
# =======================
    AESGCM = None
    SALT_SIZE = 16
    NONCE_SIZE = 12
    KEY_SIZE = 32  # AES256
    PBKDF2_ITERATIONS = 390_000
# =======================

def hash(data: bytes, algo: str) -> str:
    algo = algo.lower()
    if algo not in hashlib.algorithms_guaranteed:
        raise ValueError(f"Algorithm not supported: {algo}")
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()

def fromkey(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))

def filencrypt(path: str, password: str):
    if AESGCM is None:
        sys.exit("Please install: pip install cryptography")

    with open(path, "rb") as f:
        plaintext = f.read()
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = fromkey(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    out_path = path + ".enc"
    with open(out_path, "wb") as f:
        f.write(salt + nonce + ciphertext)

    print(f"Encrypted file saved to: {out_path}")

def filedecrypt(path: str, password: str):
    if AESGCM is None:
        sys.exit("Please install: pip install cryptography")

    with open(path, "rb") as f:
        raw = f.read()

    salt, nonce, ciphertext = (
        raw[:SALT_SIZE],
        raw[SALT_SIZE : SALT_SIZE + NONCE_SIZE],
        raw[SALT_SIZE + NONCE_SIZE :],
    )
    key = fromkey(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        sys.exit("Decryption failed: wrong password or corrupted file.")

    out_path = path[:-4] if path.endswith(".enc") else path + ".dec"
    with open(out_path, "wb") as f:
        f.write(plaintext)

    print(f"Decrypted file saved to: {out_path}")

def main():
    parser = argparse.ArgumentParser(description="AES-256 hash and encryption tool.")
    sub = parser.add_subparsers(dest="command", required=True)
    # for hash
    hash_parser = sub.add_parser("hash", help="Compute the hash of text or a file.")
    hash_parser.add_argument("--text", help="Text to hash.")
    hash_parser.add_argument("--file", help="Path to the file to hash.")
    hash_parser.add_argument("--algo", default="sha256", help="md5, sha1, sha256, sha512...")
    # for encrypt
    encrypt_parser = sub.add_parser("encrypt", help="Encrypt a file with AES-256-GCM.")
    encrypt_parser.add_argument("--file", required=True)
    encrypt_parser.add_argument("--password", required=True)
    # for decrypt
    decrypt_parser = sub.add_parser("decrypt", help="Decrypt a .enc file.")
    decrypt_parser.add_argument("--file", required=True)
    decrypt_parser.add_argument("--password", required=True)
    args = parser.parse_args()

    if args.command == "hash":
        if args.file:
            with open(args.file, "rb") as f:
                data = f.read()
        elif args.text is not None:
            data = args.text.encode("utf-8")
        else:
            sys.exit("Provide --text or --file.")
        print(f"{args.algo.upper()}: {hash(data, args.algo)}")
    elif args.command == "encrypt":
        filencrypt(args.file, args.password)
    elif args.command == "decrypt":
        filedecrypt(args.file, args.password)
if __name__ == "__main__":
    main()