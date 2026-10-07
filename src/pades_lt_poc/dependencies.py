"""Dependencias de FastAPI: los servicios se crean una vez en el lifespan y se inyectan en los endpoints."""

from typing import Annotated

from fastapi import Depends, Request
from pyhanko.sign.timestamps import DummyTimeStamper

from .services.certificates import CertificateExtractor
from .services.inspection import CertificateInspector
from .services.signing import PdfSigner
from .services.store import CertificateStore
from .services.verification import SignatureVerifier


def get_tsa(request: Request) -> DummyTimeStamper:
    return request.app.state.tsa_engine


def get_signer(request: Request) -> PdfSigner:
    return request.app.state.signer


def get_verifier(request: Request) -> SignatureVerifier:
    return request.app.state.verifier


def get_certificate_extractor(request: Request) -> CertificateExtractor:
    return request.app.state.certificate_extractor


def get_certificate_inspector(request: Request) -> CertificateInspector:
    return request.app.state.certificate_inspector


def get_certificate_store(request: Request) -> CertificateStore:
    return request.app.state.store


TsaDep = Annotated[DummyTimeStamper, Depends(get_tsa)]
SignerDep = Annotated[PdfSigner, Depends(get_signer)]
VerifierDep = Annotated[SignatureVerifier, Depends(get_verifier)]
CertificateExtractorDep = Annotated[CertificateExtractor, Depends(get_certificate_extractor)]
CertificateInspectorDep = Annotated[CertificateInspector, Depends(get_certificate_inspector)]
CertificateStoreDep = Annotated[CertificateStore, Depends(get_certificate_store)]
