"""Dependencias de FastAPI: los servicios se crean una vez en el lifespan (`bootstrap.build`) y se inyectan en los endpoints."""

from typing import Annotated

from fastapi import Depends, Request
from pyhanko.sign.timestamps import DummyTimeStamper

from .bootstrap import Services
from .pki import MiniPki
from .services.certificates import CertificateExtractor
from .services.inspection import CertificateInspector
from .services.signing import PdfSigner
from .services.store import CertificateStore
from .services.verification import SignatureVerifier


def services(request: Request) -> Services:
    return request.app.state.services


def get_pki(request: Request) -> MiniPki:
    return services(request).pki


def get_tsa(request: Request) -> DummyTimeStamper:
    return services(request).tsa_engine


def get_signer(request: Request) -> PdfSigner:
    return services(request).signer


def get_verifier(request: Request) -> SignatureVerifier:
    return services(request).verifier


def get_certificate_extractor(request: Request) -> CertificateExtractor:
    return services(request).certificate_extractor


def get_certificate_inspector(request: Request) -> CertificateInspector:
    return services(request).certificate_inspector


def get_certificate_store(request: Request) -> CertificateStore:
    return services(request).store


PkiDep = Annotated[MiniPki, Depends(get_pki)]
TsaDep = Annotated[DummyTimeStamper, Depends(get_tsa)]
SignerDep = Annotated[PdfSigner, Depends(get_signer)]
VerifierDep = Annotated[SignatureVerifier, Depends(get_verifier)]
CertificateExtractorDep = Annotated[CertificateExtractor, Depends(get_certificate_extractor)]
CertificateInspectorDep = Annotated[CertificateInspector, Depends(get_certificate_inspector)]
CertificateStoreDep = Annotated[CertificateStore, Depends(get_certificate_store)]
