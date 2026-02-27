#!/usr/bin/env python3

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Reticulum"))

import RNS  # noqa: E402
from RNS.Cryptography import Token, X25519PrivateKey, X25519PublicKey  # noqa: E402


def _from_hex(value):
    if value == "-":
        return None
    return bytes.fromhex(value)


def _print_error(message):
    print(message, file=sys.stderr)


def hkdf_cmd(args):
    if len(args) != 4:
        raise ValueError("hkdf expects 4 arguments")

    length = int(args[0])
    derive_from = _from_hex(args[1])
    salt = _from_hex(args[2])
    context = _from_hex(args[3])
    derived = RNS.Cryptography.hkdf(
        length=length, derive_from=derive_from, salt=salt, context=context
    )
    print(derived.hex())


def token_encrypt_fixed_iv_cmd(args):
    if len(args) != 3:
        raise ValueError("token_encrypt_fixed_iv expects 3 arguments")

    key = bytes.fromhex(args[0])
    plaintext = bytes.fromhex(args[1])
    iv = bytes.fromhex(args[2])

    token = Token(key)

    original_urandom = os.urandom

    def fixed_urandom(length):
        if length == len(iv):
            return iv
        return original_urandom(length)

    try:
        os.urandom = fixed_urandom
        encrypted = token.encrypt(plaintext)
    finally:
        os.urandom = original_urandom

    print(encrypted.hex())


def token_decrypt_cmd(args):
    if len(args) != 2:
        raise ValueError("token_decrypt expects 2 arguments")

    key = bytes.fromhex(args[0])
    token_data = bytes.fromhex(args[1])
    plaintext = Token(key).decrypt(token_data)
    print(plaintext.hex())


def identity_fixture_cmd(args):
    if len(args) != 1:
        raise ValueError("identity_fixture expects 1 argument")

    private_key = bytes.fromhex(args[0])
    identity = RNS.Identity(create_keys=False)
    identity.load_private_key(private_key)

    print(f"enc_sec={identity.prv_bytes.hex()}")
    print(f"enc_pub={identity.pub_bytes.hex()}")
    print(f"sig_sec={identity.sig_prv_bytes.hex()}")
    print(f"sig_pub={identity.sig_pub_bytes.hex()}")
    print(f"public_key={identity.get_public_key().hex()}")
    print(f"hash={identity.hash.hex()}")
    print(f"hexhash={identity.hexhash}")


def identity_sign_cmd(args):
    if len(args) != 2:
        raise ValueError("identity_sign expects 2 arguments")

    private_key = bytes.fromhex(args[0])
    message = bytes.fromhex(args[1])
    identity = RNS.Identity(create_keys=False)
    identity.load_private_key(private_key)
    signature = identity.sign(message)
    print(signature.hex())


def identity_validate_cmd(args):
    if len(args) != 3:
        raise ValueError("identity_validate expects 3 arguments")

    public_key = bytes.fromhex(args[0])
    message = bytes.fromhex(args[1])
    signature = bytes.fromhex(args[2])
    identity = RNS.Identity(create_keys=False)
    identity.load_public_key(public_key)
    print("true" if identity.validate(signature, message) else "false")


def identity_encrypt_cmd(args):
    if len(args) not in (3, 4):
        raise ValueError("identity_encrypt expects 3 or 4 arguments")

    public_key = bytes.fromhex(args[0])
    plaintext = bytes.fromhex(args[1])
    ephemeral_private_key = _from_hex(args[2])
    ratchet_public_key = _from_hex(args[3]) if len(args) == 4 else None

    identity = RNS.Identity(create_keys=False)
    identity.load_public_key(public_key)

    if ephemeral_private_key is None:
        if ratchet_public_key is None:
            ciphertext = identity.encrypt(plaintext)
        else:
            ciphertext = identity.encrypt(plaintext, ratchet=ratchet_public_key)
    else:
        ephemeral = X25519PrivateKey.from_private_bytes(ephemeral_private_key)
        ephemeral_pub_bytes = ephemeral.public_key().public_bytes()

        if ratchet_public_key is None:
            target_public_key = identity.pub
        else:
            target_public_key = X25519PublicKey.from_public_bytes(ratchet_public_key)

        shared_key = ephemeral.exchange(target_public_key)
        derived_key = RNS.Cryptography.hkdf(
            length=RNS.Identity.DERIVED_KEY_LENGTH,
            derive_from=shared_key,
            salt=identity.get_salt(),
            context=identity.get_context(),
        )

        ciphertext = ephemeral_pub_bytes + Token(derived_key).encrypt(plaintext)

    print(ciphertext.hex())


def identity_decrypt_cmd(args):
    if len(args) not in (2, 4):
        raise ValueError("identity_decrypt expects 2 or 4 arguments")

    private_key = bytes.fromhex(args[0])
    ciphertext = bytes.fromhex(args[1])
    identity = RNS.Identity(create_keys=False)
    identity.load_private_key(private_key)

    ratchets = None
    enforce_ratchets = False

    if len(args) == 4:
        ratchets_arg = args[2]
        enforce_ratchets = args[3] == "1"

        if ratchets_arg not in ("", "-"):
            ratchets = [
                bytes.fromhex(item) for item in ratchets_arg.split(",") if item != ""
            ]

    plaintext = identity.decrypt(
        ciphertext,
        ratchets=ratchets,
        enforce_ratchets=enforce_ratchets,
    )

    if plaintext is None:
        print("none")
    else:
        print(plaintext.hex())


def destination_name_cmd(args):
    if len(args) != 3:
        raise ValueError("destination_name expects 3 arguments")

    identity_hash = _from_hex(args[0])
    app_name = args[1]
    aspects = [] if args[2] in ("", "-") else args[2].split(",")

    if identity_hash is None:
        name = RNS.Destination.expand_name(None, app_name, *aspects)
    else:

        class IdentityHashStub:
            def __init__(self, hexhash):
                self.hexhash = hexhash

        name = RNS.Destination.expand_name(
            IdentityHashStub(identity_hash.hex()), app_name, *aspects
        )

    print(name)


def destination_hash_cmd(args):
    if len(args) != 3:
        raise ValueError("destination_hash expects 3 arguments")

    identity_hash = _from_hex(args[0])
    app_name = args[1]
    aspects = [] if args[2] in ("", "-") else args[2].split(",")
    digest = RNS.Destination.hash(identity_hash, app_name, *aspects)
    print(digest.hex())


def destination_new_cmd(args):
    if len(args) != 4:
        raise ValueError("destination_new expects 4 arguments")

    direction = int(args[0])
    destination_type = int(args[1])
    app_name = args[2]
    aspects = [] if args[3] in ("", "-") else args[3].split(",")

    RNS.Destination(None, direction, destination_type, app_name, *aspects)
    print("ok")


class _PacketDestinationStub:
    def __init__(self, destination_hash, destination_type):
        self.hash = destination_hash
        self.type = destination_type

    def encrypt(self, plaintext):
        return plaintext


def packet_pack_cmd(args):
    if len(args) != 10:
        raise ValueError("packet_pack expects 10 arguments")

    header_type = int(args[0])
    context_flag = int(args[1])
    transport_type = int(args[2])
    destination_type = int(args[3])
    packet_type = int(args[4])
    hops = int(args[5])
    destination_hash = bytes.fromhex(args[6])
    context = int(args[7])
    data = bytes.fromhex(args[8])
    transport_id = _from_hex(args[9])

    destination = _PacketDestinationStub(destination_hash, destination_type)

    packet = RNS.Packet(
        destination,
        data,
        packet_type=packet_type,
        context=context,
        transport_type=transport_type,
        header_type=header_type,
        transport_id=transport_id,
        create_receipt=False,
        context_flag=context_flag,
    )

    packet.hops = hops
    packet.pack()
    print(packet.raw.hex())


def packet_unpack_cmd(args):
    if len(args) != 1:
        raise ValueError("packet_unpack expects 1 argument")

    raw = bytes.fromhex(args[0])
    packet = RNS.Packet(None, raw)
    success = packet.unpack()

    print(f"success={'true' if success else 'false'}")

    if success:
        print(f"header_type={packet.header_type}")
        print(f"context_flag={packet.context_flag}")
        print(f"transport_type={packet.transport_type}")
        print(f"destination_type={packet.destination_type}")
        print(f"packet_type={packet.packet_type}")
        print(f"hops={packet.hops}")
        print(f"destination_hash={packet.destination_hash.hex()}")
        print(
            f"transport_id={packet.transport_id.hex() if packet.transport_id else '-'}"
        )
        print(f"context={packet.context}")
        print(f"data={packet.data.hex()}")


def packet_hash_cmd(args):
    if len(args) != 1:
        raise ValueError("packet_hash expects 1 argument")

    raw = bytes.fromhex(args[0])
    packet = RNS.Packet(None, raw)
    success = packet.unpack()

    print(f"success={'true' if success else 'false'}")

    if success:
        print(f"hashable_part={packet.get_hashable_part().hex()}")
        print(f"hash={packet.get_hash().hex()}")
        print(f"truncated_hash={packet.getTruncatedHash().hex()}")


def packet_malformed_batch_cmd(args):
    if len(args) == 0:
        raise ValueError("packet_malformed_batch expects at least 1 argument")

    for raw_hex in args:
        raw = bytes.fromhex(raw_hex)

        unpack_packet = RNS.Packet(None, raw)
        unpack_success = unpack_packet.unpack()

        hash_packet = RNS.Packet(None, raw)
        hash_success = hash_packet.unpack()

        print(
            f"unpack_success={'true' if unpack_success else 'false'} "
            f"hash_success={'true' if hash_success else 'false'}"
        )


COMMANDS = {
    "hkdf": hkdf_cmd,
    "token_encrypt_fixed_iv": token_encrypt_fixed_iv_cmd,
    "token_decrypt": token_decrypt_cmd,
    "identity_fixture": identity_fixture_cmd,
    "identity_sign": identity_sign_cmd,
    "identity_validate": identity_validate_cmd,
    "identity_encrypt": identity_encrypt_cmd,
    "identity_decrypt": identity_decrypt_cmd,
    "destination_name": destination_name_cmd,
    "destination_hash": destination_hash_cmd,
    "destination_new": destination_new_cmd,
    "packet_pack": packet_pack_cmd,
    "packet_unpack": packet_unpack_cmd,
    "packet_hash": packet_hash_cmd,
    "packet_malformed_batch": packet_malformed_batch_cmd,
}


def main():
    if len(sys.argv) < 2:
        _print_error(
            f"Expected command, available: {', '.join(sorted(COMMANDS.keys()))}"
        )
        return 2

    command = sys.argv[1]
    args = sys.argv[2:]

    if command not in COMMANDS:
        _print_error(f"Unknown command '{command}'")
        return 2

    try:
        COMMANDS[command](args)
    except Exception as exc:
        _print_error(str(exc))
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
