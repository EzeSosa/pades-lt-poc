"""`Clock` con el reloj del sistema."""

from datetime import UTC, datetime


class SystemClock:
    """Implementa `application.ports.Clock`: la hora del sistema, en UTC."""

    def now(self) -> datetime:
        return datetime.now(UTC)
