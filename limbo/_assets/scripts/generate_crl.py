from abc import abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache, cached_property
from subprocess import CompletedProcess, run
from typing import Literal, cast, override

import jinja2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.extensions import SubjectKeyIdentifier
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from limbo._assets import ASSETS_DIR_RW
from limbo.assets import CertificatePair, ext
from limbo.testcases._core import Builder

OUT_PATH = ASSETS_DIR_RW
builder = Builder("", "")
jinja = jinja2.Environment(loader=jinja2.FileSystemLoader([OUT_PATH]))


@cache
def setup() -> tuple[CertificatePair, CertificatePair, jinja2.Template]:
    root = builder.root_ca()
    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "revoked.example.com"),
            ]
        ),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(x509.SubjectAlternativeName([x509.DNSName("revoked.example.com")]), critical=False),
    )

    (OUT_PATH / "crl_cases_ca.pem").write_text(root.cert_pem)
    (OUT_PATH / "crl_cases_ca_key.pem").write_text(root.key_pem)
    (OUT_PATH / "crl_cases_leaf.pem").write_text(leaf.cert_pem)
    (OUT_PATH / "crl_cases_leaf_key.pem").write_text(leaf.key_pem)

    crl_template = jinja.get_template("crl_template.txt")
    return root, leaf, crl_template


@dataclass(frozen=True)
class DerAscii:
    @abstractmethod
    def to_der_ascii(self) -> str: ...


@dataclass(frozen=True)
class Time(DerAscii):
    time: datetime

    @cached_property
    def utc(self) -> datetime:
        return self.time.astimezone(UTC)

    @abstractmethod
    def value(self) -> str: ...

    @override
    def to_der_ascii(self) -> str:
        return f'{type(self).__name__} {{ "{self.value()}" }}'


@dataclass(frozen=True)
class GeneralizedTime(Time):
    @override
    def value(self) -> str:
        return self.utc.strftime("%Y%m%d%H%M%SZ")


@dataclass(frozen=True)
class UTCTime(Time):
    @override
    def value(self) -> str:
        return self.utc.strftime("%y%m%d%H%M%SZ")


@dataclass(frozen=True)
class RevokedCertificate:
    serial: int
    revoke_at: Time

    @cached_property
    def serial_hex_bytes(self) -> str:
        return self.serial.to_bytes(20).hex()


def der_ascii(
    tool: Literal["der2ascii"] | Literal["ascii2der"],
    args: list[str],
    *,
    input: bytes | None = None,
    capture_output: bool = False,
) -> CompletedProcess:
    return run(
        [
            "go",
            "run",
            f"github.com/google/der-ascii/cmd/{tool}@latest",
            *args,
        ],
        input=input,
        capture_output=capture_output,
    )


def tlv_encode(ty: bytes, val: bytes) -> bytes:
    # short form
    if len(val) < 128:
        return ty + bytes([len(val).to_bytes()[0] & ~(0b1 << 7)]) + val

    # long form
    length = len(val).to_bytes(4).lstrip(b"\x00")
    return ty + bytes([len(length) | (0b1 << 7)]) + length + val


def tlv_decode(tlv: bytes) -> tuple[bytes, bytes]:
    type = tlv[:1]
    raw_length = tlv[1]
    body = tlv[2:]

    is_short_form = raw_length < 128
    if is_short_form:
        length = raw_length
    else:
        length_len = raw_length & ~(0b1 << 7)
        length = int.from_bytes(body[:length_len])
        body = body[length_len:]

    assert len(body) == length, (
        f"DER item has wrong length: expected {length}, found {len(body)};\n"
        f"tlv: {tlv.hex()}\n"
        f"type: {type.hex()}\n"
        f"body: {body.hex()}\n"
    )

    return type, body


def gen_crl_test(
    name: str,
    *,
    version: int = 1,
    last_update: Time = UTCTime(datetime(year=2025, month=1, day=1)),
    next_update: Time = UTCTime(datetime(year=2025, month=1, day=30)),
) -> None:
    root, leaf, crl_template = setup()
    key = cast(ec.EllipticCurvePrivateKey, root.key)

    ski = root.cert.extensions.get_extension_for_class(SubjectKeyIdentifier)
    crl_ascii = crl_template.render(
        {
            "version": version,
            "ski": ski.value.public_bytes(),
            "last_update": last_update,
            "next_update": next_update,
            "certs": [
                # revoke on 2025-01-02
                RevokedCertificate(
                    serial=leaf.cert.serial_number,
                    revoke_at=UTCTime(datetime(year=2025, month=1, day=2)),
                )
            ],
        }
    )

    tbs_crl = der_ascii("ascii2der", [], input=crl_ascii.encode(), capture_output=True)
    assert tbs_crl.returncode == 0, "ascii2der failed"

    sig = key.sign(tbs_crl.stdout, ec.ECDSA(hashes.SHA256()))

    sequence = b"\x30"
    bitstring = b"\x03"

    ecdsa_with_sha256 = bytes.fromhex("06 08 2A 86 48 CE 3D 04 03 02")
    signature_algorithm = tlv_encode(sequence, ecdsa_with_sha256)
    signature_bits = tlv_encode(bitstring, b"\x00" + sig)
    signature = tlv_encode(sequence, signature_bits)

    _, tbs_body = tlv_decode(tbs_crl.stdout)

    (OUT_PATH / f"{name}.crl").write_bytes(
        tlv_encode(
            sequence,
            tbs_body + signature_algorithm + signature,
        )
    )


def main() -> None:
    gen_crl_test("bad_version", version=2)
    gen_crl_test(
        "generalized_time_2025",
        last_update=GeneralizedTime(datetime(year=2025, month=1, day=1)),
        next_update=GeneralizedTime(datetime(year=2025, month=1, day=30)),
    )


if __name__ == "__main__":
    main()
