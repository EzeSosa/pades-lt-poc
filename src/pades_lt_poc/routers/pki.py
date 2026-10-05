"""Certificados y CRLs de las CAs, y revocación manual para probar los casos negativos."""

from fastapi import APIRouter, HTTPException, Response

from .. import pki

router = APIRouter(prefix="/pki", tags=["PKI"])


def _ca(name: str) -> str:
    if name not in pki.CAS:
        raise HTTPException(404, f"CA desconocida, usar: {', '.join(pki.CAS)}")
    return name


@router.get("/{ca}.crt")
def get_ca_cert(ca: str) -> Response:
    return Response(pki.entity(_ca(ca)).cert_path.read_bytes(), media_type="application/x-pem-file")


@router.get("/{ca}.crl")
def get_crl(ca: str) -> Response:
    return Response(pki.build_crl(_ca(ca)), media_type="application/pkix-crl")


@router.post("/revoke/{who}")
def revoke(who: str) -> dict:
    """Sólo para probar: revoca un certificado y las próximas firmas fallarán."""
    if who not in pki.ISSUER_OF or who == pki.OCSP_RESPONDER:
        raise HTTPException(404, "usar 'intermediate', 'signer' o 'tsa'")
    return {"revoked": who, "serial": pki.revoke(who)}


@router.post("/unrevoke-all")
def unrevoke_all() -> dict:
    pki.unrevoke_all()
    return {"ok": True}
