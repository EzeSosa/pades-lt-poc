"""El certificado de dominio: vigencia, tipo de CA e identidad. Python puro: sin PKI ni bibliotecas."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from pades_lt_poc.domain.certificates import CaKind, Certificate, ValidityStatus

NOT_BEFORE = datetime(2026, 1, 1, tzinfo=UTC)
NOT_AFTER = datetime(2027, 1, 1, tzinfo=UTC)


def cert(**changes) -> Certificate:
    base = Certificate(
        der=b"der",
        sha256="aa" * 32,
        sha1="bb" * 20,
        subject="CN=Prueba",
        issuer="CN=Emisor",
        serial_number=1,
        not_before=NOT_BEFORE,
        not_after=NOT_AFTER,
        is_ca=False,
        self_signed=False,
    )
    return replace(base, **changes)


@pytest.mark.parametrize(
    ("now", "status"),
    [
        (NOT_BEFORE - timedelta(seconds=1), ValidityStatus.NOT_YET_VALID),
        (NOT_BEFORE, ValidityStatus.VALID),  # los extremos son vigentes
        (NOT_AFTER, ValidityStatus.VALID),
        (NOT_AFTER + timedelta(seconds=1), ValidityStatus.EXPIRED),
    ],
)
def test_validity_status(now, status):
    assert cert().validity_status(now) is status


def test_validity_status_is_the_api_value():
    """Los valores son los que devuelve la API (`validity.status`, `validity_status`)."""
    assert [s.value for s in ValidityStatus] == ["valid", "expired", "not_yet_valid"]


def test_days_left_counts_whole_days_and_goes_negative():
    assert cert().days_left(NOT_AFTER - timedelta(days=10, hours=1)) == 10
    assert cert().days_left(NOT_AFTER + timedelta(hours=1)) == -1


@pytest.mark.parametrize(
    ("is_ca", "self_signed", "kind"),
    [(True, True, CaKind.ROOT), (True, False, CaKind.INTERMEDIATE), (False, True, None), (False, False, None)],
)
def test_ca_kind(is_ca, self_signed, kind):
    """Una hoja autofirmada no es raíz: sólo una CA tiene tipo."""
    assert cert(is_ca=is_ca, self_signed=self_signed).ca_kind is kind


def test_identity_is_the_der():
    """Los demás campos se derivan del DER: no cuentan para la igualdad ni el hash."""
    assert cert() == cert(subject="CN=Otro", is_ca=True)
    assert cert() != cert(der=b"otro der")
    assert len({cert(), cert(sha256="cc" * 32)}) == 1
