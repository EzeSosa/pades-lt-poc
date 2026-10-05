"""TSA RFC 3161 de la PoC."""

from pyhanko.keys import load_cert_from_pemder, load_private_key_from_pemder
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko_certvalidator.registry import SimpleCertificateStore

from .. import pki


def load_tsa() -> DummyTimeStamper:
    """El "motor" de la TSA: pyHanko ya trae un emisor de tokens RFC 3161.

    La app lo expone por HTTP en /tsa para que la firma lo consuma como si
    fuera una TSA externa.
    """
    root = load_cert_from_pemder(str(pki.entity(pki.ROOT).cert_path))
    intermediate = load_cert_from_pemder(str(pki.entity(pki.INTERMEDIATE).cert_path))
    tsa_cert = load_cert_from_pemder(str(pki.entity(pki.TSA).cert_path))
    return DummyTimeStamper(
        tsa_cert=tsa_cert,
        tsa_key=load_private_key_from_pemder(str(pki.entity(pki.TSA).key_path), passphrase=None),
        certs_to_embed=SimpleCertificateStore.from_certs([tsa_cert, intermediate, root]),
    )
