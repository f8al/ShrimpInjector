import hashlib
import os
import sys

KEYING_PROPERTIES = ("hostname", "domain", "user", "machineguid")


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def aes_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
    except ImportError:
        print("[-] AES encryption requires the 'cryptography' package.", file=sys.stderr)
        print("    Install with: pip install cryptography", file=sys.stderr)
        print("    Or use -e xor for XOR encryption (no dependencies).", file=sys.stderr)
        sys.exit(1)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def parse_keying(spec: str) -> dict:
    result = {}
    for pair in spec.split(","):
        pair = pair.strip()
        if "=" not in pair:
            print(f"[-] Invalid keying spec: {pair} (expected name=value)", file=sys.stderr)
            sys.exit(1)
        name, value = pair.split("=", 1)
        name = name.strip().lower()
        if name not in KEYING_PROPERTIES:
            print(f"[-] Unknown keying property: {name}", file=sys.stderr)
            print(f"    Valid: {', '.join(KEYING_PROPERTIES)}", file=sys.stderr)
            sys.exit(1)
        result[name] = value.strip()
    return result


def derive_key(salt: bytes, keying: dict) -> bytes:
    parts = []
    for name in sorted(keying.keys()):
        parts.append(f"{name}={keying[name].upper()}\n")
    keying_str = "".join(parts)
    return hashlib.sha256(salt + keying_str.encode("utf-8")).digest()


def generate_key(encryption: str, key_hex: str = None) -> bytes:
    if key_hex:
        key = bytes.fromhex(key_hex)
        if encryption == "aes" and len(key) != 32:
            print(f"[-] AES-256 key must be 32 bytes (64 hex chars), got {len(key)}", file=sys.stderr)
            sys.exit(1)
        return key
    return os.urandom(32 if encryption == "aes" else 16)


def generate_iv(iv_hex: str = None) -> bytes:
    if iv_hex:
        iv = bytes.fromhex(iv_hex)
        if len(iv) != 16:
            print(f"[-] AES IV must be 16 bytes (32 hex chars), got {len(iv)}", file=sys.stderr)
            sys.exit(1)
        return iv
    return os.urandom(16)
