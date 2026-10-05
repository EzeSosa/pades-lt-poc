"""Respondedor OCSP (RFC 6960) para los certificados emitidos por la intermedia."""

import base64

from fastapi import APIRouter, Request, Response

from .. import pki

router = APIRouter(prefix="/ocsp", tags=["OCSP"])


@router.post("")
async def ocsp_post(request: Request) -> Response:
    return Response(pki.ocsp_respond(await request.body()), media_type="application/ocsp-response")


@router.get("/{b64_request:path}")
def ocsp_get(b64_request: str) -> Response:
    # RFC 6960 Apéndice A.1: GET {url}/{url-encoding de base64(DER)}
    return Response(
        pki.ocsp_respond(base64.b64decode(b64_request)), media_type="application/ocsp-response"
    )
