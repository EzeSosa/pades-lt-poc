"""Dependencias de FastAPI: los servicios se crean una vez en el lifespan (`bootstrap.build`) y se inyectan en los endpoints."""

from typing import Annotated

from fastapi import Depends, Request
from pyhanko.sign.timestamps import DummyTimeStamper

from .application.ports import Clock
from .application.use_cases.certificate_chains import ExtractCertificateChains
from .application.use_cases.certificate_source import CertificateSource
from .application.use_cases.inspect_certificates import InspectCertificates
from .bootstrap import Services
from .pki import MiniPki
from .services.signing import PdfSigner
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


def get_extract_chains(request: Request) -> ExtractCertificateChains:
    return services(request).extract_chains


def get_inspect_certificates(request: Request) -> InspectCertificates:
    return services(request).inspect_certificates


def get_certificate_source(request: Request) -> CertificateSource:
    return services(request).source


def get_clock(request: Request) -> Clock:
    return services(request).clock


PkiDep = Annotated[MiniPki, Depends(get_pki)]
TsaDep = Annotated[DummyTimeStamper, Depends(get_tsa)]
SignerDep = Annotated[PdfSigner, Depends(get_signer)]
VerifierDep = Annotated[SignatureVerifier, Depends(get_verifier)]
ExtractCertificateChainsDep = Annotated[ExtractCertificateChains, Depends(get_extract_chains)]
InspectCertificatesDep = Annotated[InspectCertificates, Depends(get_inspect_certificates)]
CertificateSourceDep = Annotated[CertificateSource, Depends(get_certificate_source)]
ClockDep = Annotated[Clock, Depends(get_clock)]
