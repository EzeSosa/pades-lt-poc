"""Búsqueda de un certificado en una CRL, indexada.

pyhanko-certvalidator busca el serial de cada certificado recorriendo la lista de revocados
con asn1crypto, en Python, entrada por entrada (`find_cert_in_list`). Con la CRL de la AC
ONTI (~9 MB, ~240 mil entradas) cada recorrido tarda ~2 s, y en una verificación se hacen
varios (por firma, y por cada copia de la CRL: la del DSS y la descargada). Para un
certificado no revocado, el caso común, el recorrido es completo.

Acá se reemplaza esa función por una que primero consulta un índice de seriales armado con
`cryptography` (el parser en Rust: ~0,15 s para esa CRL) y cacheado por CRL:

- Serial ausente (no revocado): se responde enseguida, sin recorrer nada.
- Serial presente (revocado): se delega en la función original, que arma la fecha y el
  motivo y controla las extensiones críticas con su semántica exacta. Es el caso raro.
- CRL indirecta (alguna entrada con `certificateIssuer`) o que `cryptography` no lee: se
  delega siempre, porque el emisor de cada entrada depende de las anteriores.

Es un parche sobre una función interna de pyhanko-certvalidator: al actualizarlo, revisar
que `validate_crl.find_cert_in_list` siga existiendo con la misma firma (los tests lo cubren).
"""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict

from asn1crypto import crl as asn1_crl
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from pyhanko_certvalidator.revinfo import validate_crl

MAX_INDEXES = 16  # CRLs indexadas en memoria (~16 MB la de la ONTI)

# El OID de la extensión certificateIssuer (2.5.29.29) codificado en DER. Si no aparece en
# toda la CRL, ninguna entrada la tiene: misma heurística que usa pyhanko-certvalidator.
_CERTIFICATE_ISSUER_OID = bytes.fromhex("0603551d1d")

_original = validate_crl.find_cert_in_list
_indexes: OrderedDict[bytes, frozenset[int] | None] = OrderedDict()
_lock = threading.Lock()


def _build_index(der: bytes) -> frozenset[int] | None:
    """Los seriales revocados de la CRL, o None si hay que delegar en pyHanko."""
    if _CERTIFICATE_ISSUER_OID in der:
        return None
    try:
        return frozenset(r.serial_number for r in x509.load_der_x509_crl(der))
    except ValueError:
        return None


def serial_index(certificate_list: asn1_crl.CertificateList) -> frozenset[int] | None:
    der = certificate_list.dump()
    key = hashlib.sha256(der).digest()
    with _lock:
        if key in _indexes:
            _indexes.move_to_end(key)
            return _indexes[key]
    index = _build_index(der)
    with _lock:
        _indexes[key] = index
        while len(_indexes) > MAX_INDEXES:
            _indexes.popitem(last=False)
    return index


def find_cert_in_list(cert, cert_issuer_name, certificate_list, crl_authority_name):
    """Misma firma y resultado que `validate_crl.find_cert_in_list`: (fecha, motivo) o (None, None)."""
    index = serial_index(certificate_list)
    if index is None:
        return _original(cert, cert_issuer_name, certificate_list, crl_authority_name)
    # Sin entradas indirectas, todas son del emisor de la CRL: pyHanko no encuentra nada si
    # el certificado es de otro emisor.
    if cert_issuer_name != crl_authority_name:
        return None, None
    if isinstance(cert, asn1_x509.Certificate):
        serial = cert["tbs_certificate"]["serial_number"].native
    else:
        serial = cert["ac_info"]["serial_number"].native
    if serial not in index:
        return None, None
    return _original(cert, cert_issuer_name, certificate_list, crl_authority_name)


def install() -> None:
    """Reemplaza la búsqueda de pyhanko-certvalidator. Se puede llamar más de una vez."""
    validate_crl.find_cert_in_list = find_cert_in_list
