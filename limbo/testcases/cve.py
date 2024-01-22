"""
Public CVE testcases.
"""

from textwrap import dedent

from cryptography import x509

from limbo.assets import Certificate
from limbo.models import PeerKind, PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def cve_2024_0567(builder: Builder) -> None:
    """
    Tests CVE-2024-0567.

    Affects GnuTLS prior to 3.8.3.

    * Announcement: <https://lists.gnupg.org/pipermail/gnutls-help/2024-January/004841.html>
    * Patch: <https://gitlab.com/gnutls/gnutls/-/commit/9edbdaa84e38b1bfb53a7d72c1de44f8de373405>
    * License: [LGPL 2.1 or later](https://gitlab.com/gnutls/gnutls/-/blob/master/LICENSE)
    """

    leaf = x509.load_pem_x509_certificate(
        dedent(
            """
            /* server (signed by A1) */
            -----BEGIN CERTIFICATE-----
            MIIBqDCCAVqgAwIBAgIUejlil+8DBffazcnMNwyOOP6yCCowBQYDK2VwMBoxGDAW
            BgNVBAMTD0ludGVybWVkaWF0ZSBBMTAgFw0yNDAxMTEwNjI3MjJaGA85OTk5MTIz
            MTIzNTk1OVowNzEbMBkGA1UEChMSR251VExTIHRlc3Qgc2VydmVyMRgwFgYDVQQD
            Ew90ZXN0LmdudXRscy5vcmcwKjAFBgMrZXADIQA1ZVS0PcNeTPQMZ+FuVz82AHrj
            qL5hWEpCDgpG4M4fxaOBkjCBjzAMBgNVHRMBAf8EAjAAMBoGA1UdEQQTMBGCD3Rl
            c3QuZ251dGxzLm9yZzATBgNVHSUEDDAKBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMC
            B4AwHQYDVR0OBBYEFGtEUv+JSt+zPoO3lu0IiObZVoiNMB8GA1UdIwQYMBaAFPnY
            v6Pw0IvKSqIlb6ewHyEAmTA3MAUGAytlcANBAAS2lyc87kH/aOvNKzPjqDwUYxPA
            CfYjyaKea2d0DZLBM5+Bjnj/4aWwTKgVTJzWhLJcLtaSdVHrXqjr9NhEhQ0=
            -----END CERTIFICATE-----
            """
        ).encode()
    )

    intermediates = x509.load_pem_x509_certificates(
        dedent(
            """
            /* A1 (signed by A) */
            -----BEGIN CERTIFICATE-----
            MIIBUjCCAQSgAwIBAgIUe/R+NVp04e74ySw2qgI6KZgFR20wBQYDK2VwMBExDzAN
            BgNVBAMTBlJvb3QgQTAgFw0yNDAxMTEwNjI1MDFaGA85OTk5MTIzMTIzNTk1OVow
            GjEYMBYGA1UEAxMPSW50ZXJtZWRpYXRlIEExMCowBQYDK2VwAyEAlkTNqwz973sy
            u3whMjSiUMs77CZu5YA7Gi5KcakExrKjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYD
            VR0PAQH/BAQDAgIEMB0GA1UdDgQWBBT52L+j8NCLykqiJW+nsB8hAJkwNzAfBgNV
            HSMEGDAWgBRbYgOkRGsd3Z74+CauX4htzLg0lzAFBgMrZXADQQBM0NBaFVPd3cTJ
            DSaZNT34fsHuJk4eagpn8mBxKQpghq4s8Ap+nYtp2KiXjcizss53PeLXVnkfyLi0
            TLVBHvUJ
            -----END CERTIFICATE-----
            /* A (signed by B) */
            -----BEGIN CERTIFICATE-----
            MIIBSDCB+6ADAgECAhQtdJpg+qlPcLoRW8iiztJUD4xNvDAFBgMrZXAwETEPMA0G
            A1UEAxMGUm9vdCBCMCAXDTI0MDExMTA2MTk1OVoYDzk5OTkxMjMxMjM1OTU5WjAR
            MQ8wDQYDVQQDEwZSb290IEEwKjAFBgMrZXADIQA0vDYyg3tgotSETL1Wq2hBs32p
            WbnINkmOSNmOiZlGHKNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
            AgQwHQYDVR0OBBYEFFtiA6REax3dnvj4Jq5fiG3MuDSXMB8GA1UdIwQYMBaAFJFA
            s2rg6j8w9AKItRnOOOjG2FG6MAUGAytlcANBAPv674p9ek5GjRcRfVQhgN+kQlHU
            u774wL3Vx3fWA1E7+WchdMzcHrPoa5OKtKmxjIKUTO4SeDZL/AVpvulrWwk=
            -----END CERTIFICATE-----
            /* A (signed by C) */
            -----BEGIN CERTIFICATE-----
            MIIBSDCB+6ADAgECAhReNpCiVn7eFDUox3mvM5qE942AVzAFBgMrZXAwETEPMA0G
            A1UEAxMGUm9vdCBDMCAXDTI0MDExMTA2MjEyMVoYDzk5OTkxMjMxMjM1OTU5WjAR
            MQ8wDQYDVQQDEwZSb290IEIwKjAFBgMrZXADIQAYX92hS97OGKbMzwrD7ReVifwM
            3iz5tnfQHWQSkvvYMKNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
            AgQwHQYDVR0OBBYEFJFAs2rg6j8w9AKItRnOOOjG2FG6MB8GA1UdIwQYMBaAFEh/
            XKjIuMeEavX5QVoy39Q+GhnwMAUGAytlcANBAIwghH3gelXty8qtoTGIEJb0+EBv
            BH4YOUh7TamxjxkjvvIhDA7ZdheofFb7NrklJco7KBcTATUSOvxakYRP9Q8=
            -----END CERTIFICATE-----
            /* B1 (signed by B) */
            -----BEGIN CERTIFICATE-----
            MIIBUjCCAQSgAwIBAgIUfpmrVDc1XBA5/7QYMyGBuB9mTtUwBQYDK2VwMBExDzAN
            BgNVBAMTBlJvb3QgQjAgFw0yNDAxMTEwNjI1MjdaGA85OTk5MTIzMTIzNTk1OVow
            GjEYMBYGA1UEAxMPSW50ZXJtZWRpYXRlIEIxMCowBQYDK2VwAyEAh6ZTuJWsweVB
            a5fsye5iq89kWDC2Y/Hlc0htLmjzMP+jYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYD
            VR0PAQH/BAQDAgIEMB0GA1UdDgQWBBTMQu37PKyLjKfPODZgxYCaayff+jAfBgNV
            HSMEGDAWgBSRQLNq4Oo/MPQCiLUZzjjoxthRujAFBgMrZXADQQBblmguY+lnYvOK
            rAZJnqpEUGfm1tIFyu3rnlE7WOVcXRXMIoNApLH2iHIipQjlvNWuSBFBTC1qdewh
            /e+0cgQB
            -----END CERTIFICATE-----
            /* B (signed by A) */
            -----BEGIN CERTIFICATE-----
            MIIBSDCB+6ADAgECAhRpEm+dWNX6DMZh/nottkFfFFrXXDAFBgMrZXAwETEPMA0G
            A1UEAxMGUm9vdCBBMCAXDTI0MDExMTA2MTcyNloYDzk5OTkxMjMxMjM1OTU5WjAR
            MQ8wDQYDVQQDEwZSb290IEIwKjAFBgMrZXADIQAYX92hS97OGKbMzwrD7ReVifwM
            3iz5tnfQHWQSkvvYMKNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
            AgQwHQYDVR0OBBYEFJFAs2rg6j8w9AKItRnOOOjG2FG6MB8GA1UdIwQYMBaAFFti
            A6REax3dnvj4Jq5fiG3MuDSXMAUGAytlcANBAFvmcK3Ida5ViVYDzxKVLPcPsCHe
            3hxz99lBrerJC9iJSvRYTJoPBvjTxDYnBn5EFrQYMrUED+6i71lmGXNU9gs=
            -----END CERTIFICATE-----
            /* B (signed by C) */
            -----BEGIN CERTIFICATE-----
            MIIBSDCB+6ADAgECAhReNpCiVn7eFDUox3mvM5qE942AVzAFBgMrZXAwETEPMA0G
            A1UEAxMGUm9vdCBDMCAXDTI0MDExMTA2MjEyMVoYDzk5OTkxMjMxMjM1OTU5WjAR
            MQ8wDQYDVQQDEwZSb290IEIwKjAFBgMrZXADIQAYX92hS97OGKbMzwrD7ReVifwM
            3iz5tnfQHWQSkvvYMKNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
            AgQwHQYDVR0OBBYEFJFAs2rg6j8w9AKItRnOOOjG2FG6MB8GA1UdIwQYMBaAFEh/
            XKjIuMeEavX5QVoy39Q+GhnwMAUGAytlcANBAIwghH3gelXty8qtoTGIEJb0+EBv
            BH4YOUh7TamxjxkjvvIhDA7ZdheofFb7NrklJco7KBcTATUSOvxakYRP9Q8=
            -----END CERTIFICATE-----
            /* C1 (signed by C) */
            -----BEGIN CERTIFICATE-----
            MIIBUjCCAQSgAwIBAgIUSKsfY1wD3eD2VmaaK1wt5naPckMwBQYDK2VwMBExDzAN
            BgNVBAMTBlJvb3QgQzAgFw0yNDAxMTEwNjI1NDdaGA85OTk5MTIzMTIzNTk1OVow
            GjEYMBYGA1UEAxMPSW50ZXJtZWRpYXRlIEMxMCowBQYDK2VwAyEA/t7i1chZlKkV
            qxJOrmmyATn8XnpK+nV/iT4OMHSHfAyjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYD
            VR0PAQH/BAQDAgIEMB0GA1UdDgQWBBRmpF3JjoP3NiBzE5J5ANT0bvfRmjAfBgNV
            HSMEGDAWgBRIf1yoyLjHhGr1+UFaMt/UPhoZ8DAFBgMrZXADQQAeRBXv6WCTOp0G
            3wgd8bbEGrrILfpi+qH7aj/MywgkPIlppDYRQ3jL6ASd+So/408dlE0DV9DXKBi0
            725XUUYO
            -----END CERTIFICATE-----
            /* C (signed by A) */
            -----BEGIN CERTIFICATE-----
            MIIBSDCB+6ADAgECAhRvbZv3SRTjDOiAbyFWHH4y0yMZkjAFBgMrZXAwETEPMA0G
            A1UEAxMGUm9vdCBBMCAXDTI0MDExMTA2MTg1MVoYDzk5OTkxMjMxMjM1OTU5WjAR
            MQ8wDQYDVQQDEwZSb290IEMwKjAFBgMrZXADIQDxm6Ubhsa0gSa1vBCIO5e+qZEH
            8Oocz+buNHfIJbh5NaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
            AgQwHQYDVR0OBBYEFEh/XKjIuMeEavX5QVoy39Q+GhnwMB8GA1UdIwQYMBaAFFti
            A6REax3dnvj4Jq5fiG3MuDSXMAUGAytlcANBAPl+SyiOfXJnjSWx8hFMhJ7w92mn
            tkGifCFHBpUhYcBIMeMtLw0RBLXqaaN0EKlTFimiEkLClsU7DKYrpEEJegs=
            -----END CERTIFICATE-----
            /* C (signed by B) */
            -----BEGIN CERTIFICATE-----
            MIIBSDCB+6ADAgECAhQU1OJWRVOLrGrgJiLwexd1/MwKkTAFBgMrZXAwETEPMA0G
            A1UEAxMGUm9vdCBCMCAXDTI0MDExMTA2MjAzMFoYDzk5OTkxMjMxMjM1OTU5WjAR
            MQ8wDQYDVQQDEwZSb290IEMwKjAFBgMrZXADIQDxm6Ubhsa0gSa1vBCIO5e+qZEH
            8Oocz+buNHfIJbh5NaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
            AgQwHQYDVR0OBBYEFEh/XKjIuMeEavX5QVoy39Q+GhnwMB8GA1UdIwQYMBaAFJFA
            s2rg6j8w9AKItRnOOOjG2FG6MAUGAytlcANBALXeyuj8vj6Q8j4l17VzZwmJl0gN
            bCGoKMl0J/0NiN/fQRIsdbwQDh0RUN/RN3I6DTtB20ER6f3VdnzAh8nXkQ4=
            -----END CERTIFICATE-----
            """
        ).encode()
    )

    root = x509.load_pem_x509_certificate(
        dedent(
            """
            /* A (self-signed) */
            -----BEGIN CERTIFICATE-----
            MIIBJzCB2qADAgECAhQs1Ur+gzPs1ISxs3Tbs700q0CZcjAFBgMrZXAwETEPMA0G
            A1UEAxMGUm9vdCBBMCAXDTI0MDExMTA2MTYwMFoYDzk5OTkxMjMxMjM1OTU5WjAR
            MQ8wDQYDVQQDEwZSb290IEEwKjAFBgMrZXADIQA0vDYyg3tgotSETL1Wq2hBs32p
            WbnINkmOSNmOiZlGHKNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
            AgQwHQYDVR0OBBYEFFtiA6REax3dnvj4Jq5fiG3MuDSXMAUGAytlcANBAHrVv7E9
            5scuOVCH9gNRRm8Z9SUoLakRHAPnySdg6z/kI3vOgA/OM7reArpnW8l1H2FapgpL
            bDeZ2XJH+BdVFwg=
            -----END CERTIFICATE-----
            """
        ).encode()
    )

    builder = (
        builder.server_validation()
        .trusted_certs(Certificate(root))
        .untrusted_intermediates(*[Certificate(c) for c in intermediates])
        .peer_certificate(Certificate(leaf))
        .expected_peer_name(PeerName(kind=PeerKind.DNS, value="test.gnutls.org"))
        .succeeds()
    )
