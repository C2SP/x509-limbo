from pathlib import Path
from sys import argv

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from limbo._assets import ASSETS_DIR_RW

CRL_ASSETS_PATH = ASSETS_DIR_RW / "crl"


def tlv_encode(ty: bytes, val: bytes) -> bytes:
    # short form
    if len(val) < 128:
        return ty + bytes([len(val).to_bytes()[0] & ~(0b1 << 7)]) + val

    # long form
    length = len(val).to_bytes(4).lstrip(b"\x00")
    return ty + bytes([len(length) | (0b1 << 7)]) + length + val


def sign_tbs_crl(path: Path) -> None:
    key = serialization.load_pem_private_key(
        (CRL_ASSETS_PATH / "crl_cases_ca_key.pem").read_bytes(), None
    )
    assert isinstance(key, ec.EllipticCurvePrivateKey)

    tbs_crl = path.read_bytes()
    sig = key.sign(tbs_crl, ec.ECDSA(hashes.SHA256()))

    sequence = b"\x30"
    bitstring = b"\x03"

    ecdsa_with_sha256 = bytes.fromhex("06 08 2A 86 48 CE 3D 04 03 02")
    signature_algorithm = tlv_encode(sequence, ecdsa_with_sha256)
    signature_bits = tlv_encode(bitstring, b"\x00" + sig)

    path.write_bytes(
        tlv_encode(
            sequence,
            tbs_crl + signature_algorithm + signature_bits,
        )
    )


if __name__ == "__main__":
    assert len(argv) == 2
    sign_tbs_crl(Path(argv[1]))
