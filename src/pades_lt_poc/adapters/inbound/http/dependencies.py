"""Dependencias de FastAPI: los casos de uso se crean una vez en el lifespan (`bootstrap.build`) y se inyectan en los endpoints.

No importa `bootstrap`: los endpoints conocen los casos de uso, no cómo se arman (ni el testbed).
"""

from typing import Annotated

from fastapi import Depends, Request

from ....application.ports import Clock
from ....application.use_cases.analyze_document import AnalyzeDocument
from ....application.use_cases.certificate_chains import ExtractCertificateChains
from ....application.use_cases.certificate_source import CertificateSource
from ....application.use_cases.inspect_certificates import InspectCertificates
from ....application.use_cases.sign_pdf import SignPdf
from ....application.use_cases.verify_signatures import VerifySignatures


def services(request: Request):
    """Los `bootstrap.Services` de la app."""
    return request.app.state.services


def get_sign_pdf(request: Request) -> SignPdf:
    return services(request).sign_pdf


def get_verify_signatures(request: Request) -> VerifySignatures:
    return services(request).verify_signatures


def get_analyze_document(request: Request) -> AnalyzeDocument:
    return services(request).analyze_document


def get_extract_chains(request: Request) -> ExtractCertificateChains:
    return services(request).extract_chains


def get_inspect_certificates(request: Request) -> InspectCertificates:
    return services(request).inspect_certificates


def get_certificate_source(request: Request) -> CertificateSource:
    return services(request).source


def get_clock(request: Request) -> Clock:
    return services(request).clock


SignPdfDep = Annotated[SignPdf, Depends(get_sign_pdf)]
VerifySignaturesDep = Annotated[VerifySignatures, Depends(get_verify_signatures)]
AnalyzeDocumentDep = Annotated[AnalyzeDocument, Depends(get_analyze_document)]
ExtractCertificateChainsDep = Annotated[ExtractCertificateChains, Depends(get_extract_chains)]
InspectCertificatesDep = Annotated[InspectCertificates, Depends(get_inspect_certificates)]
CertificateSourceDep = Annotated[CertificateSource, Depends(get_certificate_source)]
ClockDep = Annotated[Clock, Depends(get_clock)]
