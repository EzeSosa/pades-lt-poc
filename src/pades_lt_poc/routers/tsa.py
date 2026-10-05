"""TSA RFC 3161."""

from asn1crypto import tsp
from fastapi import APIRouter, HTTPException, Request, Response

from ..dependencies import TsaDep

router = APIRouter(tags=["TSA"])


@router.post("/tsa")
async def tsa(request: Request, engine: TsaDep) -> Response:
    if request.headers.get("content-type") != "application/timestamp-query":
        raise HTTPException(415, "se esperaba application/timestamp-query")
    req = tsp.TimeStampReq.load(await request.body())
    resp = await engine.async_request_tsa_response(req)
    return Response(resp.dump(), media_type="application/timestamp-reply")
