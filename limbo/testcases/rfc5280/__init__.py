"""
RFC5280 profile tests.
"""

import random
from datetime import datetime

from cryptography import x509

from limbo.assets import ASSETS_PATH, Certificate, ext
from limbo.models import Feature, KnownEKUs, PeerName
from limbo.testcases._core import Builder, testcase

from .aki import *  # noqa: F403
from .nc import *  # noqa: F403
from .san import *  # noqa: F403
from .ski import *  # noqa: F403
from .validity import *  # noqa: F403


@testcase
def ee_empty_issuer(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is invalid solely because of the EE cert's construction:
    it has an empty issuer name, which isn't allowed under the RFC 5280 profile.
    """
    # Intentionally empty issuer name.
    issuer = x509.Name([])
    subject = x509.Name.from_rfc4514_string("CN=empty-issuer")
    root = builder.root_ca(issuer=issuer, subject=subject)
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder = builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def ca_empty_subject(builder: Builder) -> None:
    """
    Produces an **invalid** chain due to an invalid CA cert.

    The CA cert contains an empty Subject `SEQUENCE`, which is disallowed
    under RFC 5280:

    > If the subject is a CA [...], then the subject field MUST be populated
    > with a non-empty distinguished name
    """

    root = builder.root_ca(subject=x509.Name([]))
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def unknown_critical_extension_ee(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE cert has an extension, 1.3.6.1.4.1.55738.666.1, that no implementation
    should recognize. As this unrecognized extension is marked as critical, a
    chain should not be built with this EE.
    """
    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        extra_extension=ext(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.55738.666.1"), b""),
            critical=True,
        ),
    )

    builder = builder.server_validation()
    builder = builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def unknown_critical_extension_root(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root has an extension, 1.3.6.1.4.1.55738.666.1, that no implementation
    should recognize. As this unrecognized extension is marked as critical, a
    chain should not be built with this root.
    """

    root = builder.root_ca(
        extra_extension=ext(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.55738.666.1"), b""),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder = builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def unknown_critical_extension_intermediate(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> intermediate (pathlen:0) -> EE
    ```

    The intermediate has an extension, 1.3.6.1.4.1.55738.666.1, that no implementation
    should recognize. As this unrecognized extension is marked as critical, a
    chain should not be built with this intermediate.
    """

    root = builder.root_ca()
    intermediate = builder.intermediate_ca(
        root,
        pathlen=0,
        extra_extension=ext(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.55738.666.1"), b""),
            critical=True,
        ),
    )
    leaf = builder.leaf_cert(intermediate)

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .untrusted_intermediates(intermediate)
        .peer_certificate(leaf)
        .fails()
    )


@testcase
def chain_untrusted_root(builder: Builder) -> None:
    """
    Produces the following chain:

    ```
    root (untrusted) -> intermediate -> EE
    ```

    The root is not in the trusted set, thus no chain should be built.
    Verification can't be achieved without trusted certificates so we add an
    unrelated root CA to create a more realistic scenario.
    """
    root = builder.root_ca()
    intermediate = builder.intermediate_ca(root, pathlen=0)
    leaf = builder.leaf_cert(intermediate)
    unrelated_root = builder.root_ca(
        issuer=x509.Name.from_rfc4514_string("CN=x509-limbo-unrelated-root")
    )

    builder = builder.server_validation()
    builder.trusted_certs(unrelated_root).untrusted_intermediates(
        root, intermediate
    ).peer_certificate(leaf).fails()


@testcase
def intermediate_ca_without_ca_bit(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> intermediate -> EE
    ```

    The intermediate CA does not have the cA bit set in BasicConstraints, thus
    no valid chain to the leaf exists per the [RFC 5280 profile]:

    > If the basic constraints extension is not present in a version 3
    > certificate, or the extension is present but the cA boolean
    > is not asserted, then the certified public key MUST NOT be used to
    > verify certificate signatures.

    [RFC 5280 profile]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
    """
    root = builder.root_ca()
    intermediate = builder.intermediate_ca(
        root,
        basic_constraints=ext(x509.BasicConstraints(False, path_length=None), critical=True),
    )
    leaf = builder.leaf_cert(intermediate)

    builder = builder.server_validation()
    builder.trusted_certs(root).untrusted_intermediates(intermediate).peer_certificate(leaf).fails()


@testcase
def intermediate_ca_missing_basic_constraints(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA -> EE
    ```

    The intermediate CA is missing the BasicConstraints extension, which is disallowed
    under the [RFC 5280 profile]:

    > Conforming CAs MUST include this extension in all CA certificates
    > that contain public keys used to validate digital signatures on
    > certificates and MUST mark the extension as critical in such
    > certificates.

    [RFC 5280 profile]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
    """
    root = builder.root_ca()
    intermediate = builder.intermediate_ca(root, basic_constraints=None)
    leaf = builder.leaf_cert(intermediate)

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def root_missing_basic_constraints(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root CA is missing the BasicConstraints extension, which is disallowed
    under the [RFC 5280 profile]:

    > Conforming CAs MUST include this extension in all CA certificates
    > that contain public keys used to validate digital signatures on
    > certificates and MUST mark the extension as critical in such
    > certificates.

    [RFC 5280 profile]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
    """
    root = builder.root_ca(basic_constraints=None)
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def root_non_critical_basic_constraints(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root CA has a non-critical BasicConstraints extension, which is disallowed
    under the [RFC 5280 profile]:

    > Conforming CAs MUST include this extension in all CA certificates
    > that contain public keys used to validate digital signatures on
    > certificates and MUST mark the extension as critical in such
    > certificates.

    [RFC 5280 profile]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
    """
    root = builder.root_ca(basic_constraints=ext(x509.BasicConstraints(True, None), critical=False))
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def root_inconsistent_ca_extensions(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root CA has BasicConstraints.cA=TRUE and KeyUsage.keyCertSign=FALSE.
    According to the [RFC 5280 profile], these two fields are related in the
    following ways:

    > If the keyCertSign bit is asserted, then the cA bit in the basic
    > constraints extension MUST also be asserted. (Section 4.2.1.3)

    and

    > If the cA boolean is not asserted, then the keyCertSign bit in the
    > key usage extension MUST NOT be asserted. (Section 4.2.1.9)

    Although the profile does not directly state that keyCertSign must be asserted
    when cA is asserted, this configuration is inconsistent and clients should
    reject it.

    [RFC 5280 profile]: https://datatracker.ietf.org/doc/html/rfc5280
    """
    root = builder.root_ca(
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        ),
    )
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def ica_ku_keycertsign(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA -> EE
    ```

    The intermediate CA includes BasicConstraints with pathLenConstraint=0 and
    KeyUsage.keyCertSign=FALSE, which is disallowed under the [RFC 5280 profile]:

    > CAs MUST NOT include the pathLenConstraint field unless the cA
    > boolean is asserted and the key usage extension asserts the
    > keyCertSign bit.

    [RFC 5280 profile]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
    """
    root = builder.root_ca()
    intermediate = builder.intermediate_ca(
        root,
        pathlen=0,
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        ),
    )
    leaf = builder.leaf_cert(intermediate)

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def leaf_ku_keycertsign(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The leaf has a BasicConstraints extension with cA=FALSE and a KeyUsage
    extension with keyCertSign=TRUE. This is disallowed under the
    [RFC 5280 profile]:

    > The cA boolean indicates whether the certified public key may be used
    > to verify certificate signatures.  If the cA boolean is not asserted,
    > then the keyCertSign bit in the key usage extension MUST NOT be
    > asserted.

    [RFC 5280 profile]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
    """
    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        basic_constraints=ext(x509.BasicConstraints(False, None), critical=True),
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def ee_aia(builder: Builder) -> None:
    """
    Produces a **valid** chain with an EE cert.

    This EE cert contains an Authority Information Access extension with a CA Issuer Access
    Description.
    """
    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        extra_extension=ext(
            x509.AuthorityInformationAccess(
                [x509.AccessDescription(x509.OID_CA_ISSUERS, x509.DNSName("example.com"))]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).succeeds()


@testcase
def ee_critical_aia_invalid(builder: Builder) -> None:
    """
    Produces a **invalid** chain with an EE cert.

    This EE cert contains an Authority Information Access extension with a CA Issuer Access
    Description. The AIA extension is marked as critical, which is disallowed
    under RFC 5280:

    > Conforming CAs MUST mark this extension as non-critical.
    """
    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        extra_extension=ext(
            x509.AuthorityInformationAccess(
                [x509.AccessDescription(x509.OID_CA_ISSUERS, x509.DNSName("example.com"))]
            ),
            critical=True,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def serial_number_too_long(builder: Builder) -> None:
    """
    Produces an **invalid** chain due to an invalid EE cert.

    The EE cert contains a serial number longer than 20 octets, which is
    disallowed under RFC 5280.
    """

    root = builder.root_ca()
    # NOTE: Intentionally generate 22 octets, since many implementations are
    # permissive of 21-octet encodings due to signedness errors.
    leaf = builder.leaf_cert(root, serial=int.from_bytes(random.randbytes(22), signed=False))

    builder = builder.server_validation().features([Feature.pedantic_serial_number])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def serial_number_zero(builder: Builder) -> None:
    """
    Produces an **invalid** chain due to an invalid EE cert.

    The EE cert contains a serial number of zero, which is disallowed
    under RFC 5280.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(root, serial=0)

    builder = builder.server_validation().features([Feature.pedantic_serial_number])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def serial_number_negative(builder: Builder) -> None:
    """
    Produces an **invalid** chain due to an invalid EE cert. Verifies against a
    saved copy of a certificate with a negative serial number from the
    `cryptography.io` test suite since the API won't allow us to create
    certificates with negative serial numbers.

    The EE cert contains a negative serial number, which is disallowed
    under RFC 5280.
    """

    cert_path = ASSETS_PATH / "negative_serial.pem"
    cert = Certificate(x509.load_pem_x509_certificate(cert_path.read_bytes()))

    builder = builder.server_validation().features([Feature.pedantic_serial_number])
    builder.trusted_certs(cert).peer_certificate(cert).expected_peer_name(
        PeerName(kind="DNS", value="gov.us")
    ).validation_time(datetime.fromisoformat("2016-09-01T00:00:00Z")).fails()


@testcase
def duplicate_extensions(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is invalid solely because of the EE cert's construction:
    it contains multiple X.509v3 extensions with the same OID, which
    is prohibited under the [RFC 5280 profile].

    > A certificate MUST NOT include more than one instance of a particular
    > extension.

    [RFC 5280 profile]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=None,
        extra_unchecked_extensions=[
            ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False),
            ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False),
        ],
    )

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="example.com"))
        .fails()
    )


@testcase
def no_keyusage(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> EE
    ```

    The EE lacks a Key Usage extension, which is not required for
    end-entity certificates under the RFC 5280 profile.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(root, key_usage=None)

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="example.com"))
        .succeeds()
    )


@testcase
def no_basicconstraints(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> EE
    ```

    The EE lacks a Basic Constraints extension, which is not required for
    end-entity certificates under the RFC 5280 profile.
    """
    root = builder.root_ca()
    leaf = builder.leaf_cert(root, basic_constraints=None)

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="example.com"))
        .succeeds()
    )


@testcase
def wrong_eku(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The chain is correctly constructed, but the EE cert contains
    an Extended Key Usage extension that contains just `id-kp-clientAuth`
    while the validator expects `id-kp-serverAuth`.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder = (
        builder.trusted_certs(root)
        .extended_key_usage([KnownEKUs.server_auth])
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="example.com"))
        .fails()
    )


@testcase
def mismatching_signature_algorithm(builder: Builder) -> None:
    """
    Verifies against a saved copy of `cryptography.io`'s chain with
    the root certificate modified to have mismatched `signatureAlgorithm`
    fields, which is prohibited under the [RFC 5280 profile].

    > A certificate MUST NOT include more than one instance of a particular
    > extension.

    [RFC 5280 profile]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2
    """
    chain_path = ASSETS_PATH / "cryptography.io_mismatched.pem"
    chain = [Certificate(c) for c in x509.load_pem_x509_certificates(chain_path.read_bytes())]

    leaf, root = chain.pop(0), chain.pop(-1)
    builder = builder.server_validation().validation_time(
        datetime.fromisoformat("2023-07-10T00:00:00Z")
    )
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .untrusted_intermediates(*chain)
        .expected_peer_name(PeerName(kind="DNS", value="cryptography.io"))
    ).fails()