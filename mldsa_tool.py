from __future__ import annotations

import argparse
import getpass
import os
import stat
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

_LEVELS = {
    44: (mldsa.MLDSA44PrivateKey, mldsa.MLDSA44PublicKey),
    65: (mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey),
    87: (mldsa.MLDSA87PrivateKey, mldsa.MLDSA87PublicKey),
}

_MAX_CONTEXT_LEN = 255


def _die(msg: str) -> "None":
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def _encode_context(context: str | None) -> bytes | None:
    if context is None:
        return None
    ctx_bytes = context.encode("utf-8")
    if len(ctx_bytes) > _MAX_CONTEXT_LEN:
        _die(
            f"context string is {len(ctx_bytes)} bytes; FIPS 204 limits it to "
            f"{_MAX_CONTEXT_LEN} bytes"
        )
    return ctx_bytes


def _read_passphrase(prompt: str, confirm: bool = False) -> bytes:
    while True:
        pw = getpass.getpass(prompt)
        if not pw:
            print("passphrase must not be empty; try again.", file=sys.stderr)
            continue
        if confirm:
            pw2 = getpass.getpass("Confirm passphrase: ")
            if pw != pw2:
                print("passphrases did not match; try again.", file=sys.stderr)
                continue
        return pw.encode("utf-8")


def _write_private_key_file(path: str, pem_bytes: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(pem_bytes)
    finally:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def cmd_keygen(args: argparse.Namespace) -> None:
    priv_cls, _ = _LEVELS[args.level]

    if os.path.exists(args.priv_out) and not args.force:
        _die(f"{args.priv_out} already exists; pass --force to overwrite")
    if os.path.exists(args.pub_out) and not args.force:
        _die(f"{args.pub_out} already exists; pass --force to overwrite")

    print(f"Generating ML-DSA-{args.level} key pair ...")
    private_key = priv_cls.generate()
    public_key = private_key.public_key()

    passphrase = _read_passphrase(
        "New passphrase to encrypt the private key: ", confirm=True
    )
    encryption = serialization.BestAvailableEncryption(passphrase)

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    _write_private_key_file(args.priv_out, priv_pem)
    with open(args.pub_out, "wb") as f:
        f.write(pub_pem)

    print(f"Wrote encrypted private key -> {args.priv_out} (mode 0600)")
    print(f"Wrote public key            -> {args.pub_out}")


def _load_private_key(path: str):
    with open(path, "rb") as f:
        data = f.read()
    passphrase = _read_passphrase(f"Passphrase for {path}: ")
    try:
        return serialization.load_pem_private_key(data, password=passphrase)
    except (ValueError, TypeError) as e:
        _die(
            f"could not load private key (wrong passphrase or corrupt file): {e}")


def _load_public_key(path: str):
    with open(path, "rb") as f:
        data = f.read()
    try:
        return serialization.load_pem_public_key(data)
    except ValueError as e:
        _die(f"could not load public key (corrupt file?): {e}")


def cmd_sign(args: argparse.Namespace) -> None:
    private_key = _load_private_key(args.priv)

    valid_types = tuple(cls for cls, _ in _LEVELS.values())
    if not isinstance(private_key, valid_types):
        _die("the supplied key is not an ML-DSA private key")

    with open(args.infile, "rb") as f:
        message = f.read()

    context = _encode_context(args.context)
    signature = private_key.sign(message, context=context)

    with open(args.sig_out, "wb") as f:
        f.write(signature)

    print(f"Signed {args.infile} ({len(message)} bytes) -> {args.sig_out}")
    print(f"Signature size: {len(signature)} bytes")


def cmd_verify(args: argparse.Namespace) -> None:
    public_key = _load_public_key(args.pub)

    valid_types = tuple(cls for _, cls in _LEVELS.values())
    if not isinstance(public_key, valid_types):
        _die("the supplied key is not an ML-DSA public key")

    with open(args.infile, "rb") as f:
        message = f.read()
    with open(args.sig, "rb") as f:
        signature = f.read()

    context = _encode_context(args.context)

    try:
        public_key.verify(signature, message, context=context)
    except InvalidSignature:
        print("INVALID: signature does not verify against this message/key/context.")
        sys.exit(1)
    else:
        print("VALID: signature verifies correctly.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="ML-DSA (FIPS 204) key generation, signing, and verification."
    )
    sub = p.add_subparsers(dest="command", required=True)

    kg = sub.add_parser("keygen", help="Generate an ML-DSA key pair.")
    kg.add_argument(
        "--level", type=int, choices=sorted(_LEVELS), default=65,
        help="ML-DSA parameter set / NIST security category (default: 65).",
    )
    kg.add_argument("--priv-out", required=True,
                    help="Output path for encrypted private key PEM.")
    kg.add_argument("--pub-out", required=True,
                    help="Output path for public key PEM.")
    kg.add_argument("--force", action="store_true",
                    help="Overwrite existing output files.")
    kg.set_defaults(func=cmd_keygen)

    sg = sub.add_parser("sign", help="Sign a file.")
    sg.add_argument("--priv", required=True,
                    help="Path to encrypted private key PEM.")
    sg.add_argument("--in", dest="infile", required=True,
                    help="Path to the message file to sign.")
    sg.add_argument("--sig-out", required=True,
                    help="Output path for the signature.")
    sg.add_argument(
        "--context", default=None,
        help="Optional domain-separation context string (<=255 bytes UTF-8).",
    )
    sg.set_defaults(func=cmd_sign)

    vf = sub.add_parser("verify", help="Verify a signature.")
    vf.add_argument("--pub", required=True, help="Path to public key PEM.")
    vf.add_argument("--in", dest="infile", required=True,
                    help="Path to the message file.")
    vf.add_argument("--sig", required=True, help="Path to the signature file.")
    vf.add_argument(
        "--context", default=None,
        help="Context string used at signing time (must match exactly).",
    )
    vf.set_defaults(func=cmd_verify)

    return p


def main() -> None:
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError:
        _die(
            "this version of the 'cryptography' package has no ML-DSA support.\n"
            "Install cryptography>=47.0.0 with an OpenSSL 3.5+ backend, e.g.:\n"
            "    pip install --upgrade 'cryptography>=47.0.0'"
        )

    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
