"""Los endpoints del testbed: certificados y CRLs de las CAs, revocación manual, OCSP y TSA."""

from __future__ import annotations

import base64
from collections.abc import Callable

from asn1crypto import tsp
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from . import Testbed
from . import pki as names


def create_router(get_testbed: Callable[[Request], Testbed]) -> APIRouter:
    """Los endpoints de `/pki`, `/ocsp` y `/tsa`. `get_testbed` saca el testbed del pedido (lo pone la app)."""
    router = APIRouter()
    router.include_router(_pki_router(get_testbed))
    router.include_router(_ocsp_router(get_testbed))
    router.include_router(_tsa_router(get_testbed))
    return router


def _ca(name: str) -> str:
    if name not in names.CAS:
        raise HTTPException(404, f"CA desconocida, usar: {', '.join(names.CAS)}")
    return name


def _pki_router(get_testbed) -> APIRouter:
    """Certificados y CRLs de las CAs, y revocación manual para probar los casos negativos."""
    router = APIRouter(prefix="/pki", tags=["PKI"])

    @router.get("/{ca}.crt")
    def get_ca_cert(ca: str, testbed: Testbed = Depends(get_testbed)) -> Response:
        return Response(testbed.pki.entity(_ca(ca)).cert_path.read_bytes(), media_type="application/x-pem-file")

    @router.get("/{ca}.crl")
    def get_crl(ca: str, testbed: Testbed = Depends(get_testbed)) -> Response:
        return Response(testbed.pki.build_crl(_ca(ca)), media_type="application/pkix-crl")

    @router.post("/revoke/{who}")
    def revoke(who: str, testbed: Testbed = Depends(get_testbed)) -> dict:
        """Sólo para probar: revoca un certificado y las próximas firmas fallarán."""
        if who not in names.ISSUER_OF or who == names.OCSP_RESPONDER:
            raise HTTPException(404, "usar 'intermediate', 'signer' o 'tsa'")
        return {"revoked": who, "serial": testbed.pki.revoke(who)}

    @router.post("/unrevoke-all")
    def unrevoke_all(testbed: Testbed = Depends(get_testbed)) -> dict:
        testbed.pki.unrevoke_all()
        return {"ok": True}

    return router


def _ocsp_router(get_testbed) -> APIRouter:
    """Respondedor OCSP (RFC 6960) para los certificados emitidos por la intermedia."""
    router = APIRouter(prefix="/ocsp", tags=["OCSP"])

    @router.post("")
    async def ocsp_post(request: Request, testbed: Testbed = Depends(get_testbed)) -> Response:
        return Response(testbed.pki.ocsp_respond(await request.body()), media_type="application/ocsp-response")

    @router.get("/{b64_request:path}")
    def ocsp_get(b64_request: str, testbed: Testbed = Depends(get_testbed)) -> Response:
        # RFC 6960 Apéndice A.1: GET {url}/{url-encoding de base64(DER)}
        return Response(
            testbed.pki.ocsp_respond(base64.b64decode(b64_request)), media_type="application/ocsp-response"
        )

    return router


def _tsa_router(get_testbed) -> APIRouter:
    """TSA RFC 3161."""
    router = APIRouter(tags=["TSA"])

    @router.post("/tsa")
    async def tsa(request: Request, testbed: Testbed = Depends(get_testbed)) -> Response:
        if request.headers.get("content-type") != "application/timestamp-query":
            raise HTTPException(415, "se esperaba application/timestamp-query")
        req = tsp.TimeStampReq.load(await request.body())
        resp = await testbed.tsa_engine.async_request_tsa_response(req)
        return Response(resp.dump(), media_type="application/timestamp-reply")

    return router
