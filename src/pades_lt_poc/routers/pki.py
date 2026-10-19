"""Certificados y CRLs de las CAs, y revocación manual para probar los casos negativos."""

from fastapi import APIRouter, HTTPException, Response

from .. import pki as pki_names
from ..dependencies import PkiDep

router = APIRouter(prefix="/pki", tags=["PKI"])


def _ca(name: str) -> str:
    if name not in pki_names.CAS:
        raise HTTPException(404, f"CA desconocida, usar: {', '.join(pki_names.CAS)}")
    return name


@router.get("/{ca}.crt")
def get_ca_cert(ca: str, pki: PkiDep) -> Response:
    return Response(pki.entity(_ca(ca)).cert_path.read_bytes(), media_type="application/x-pem-file")


@router.get("/{ca}.crl")
def get_crl(ca: str, pki: PkiDep) -> Response:
    return Response(pki.build_crl(_ca(ca)), media_type="application/pkix-crl")


@router.post("/revoke/{who}")
def revoke(who: str, pki: PkiDep) -> dict:
    """Sólo para probar: revoca un certificado y las próximas firmas fallarán."""
    if who not in pki_names.ISSUER_OF or who == pki_names.OCSP_RESPONDER:
        raise HTTPException(404, "usar 'intermediate', 'signer' o 'tsa'")
    return {"revoked": who, "serial": pki.revoke(who)}


@router.post("/unrevoke-all")
def unrevoke_all(pki: PkiDep) -> dict:
    pki.unrevoke_all()
    return {"ok": True}
