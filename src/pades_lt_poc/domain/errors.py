"""Errores de negocio. Cada adaptador de entrada decide cómo mostrarlos (la API HTTP: ver app.py y routers/)."""


class UnprocessableInput(Exception):
    """La entrada no se puede procesar. La API lo devuelve como 422."""


class UnprocessablePdf(UnprocessableInput):
    """El PDF no se puede procesar (no es un PDF, está cifrado, no tiene firmas, no se pudo firmar, etc.)."""


class UnprocessableCertificate(UnprocessableInput):
    """Lo recibido no es un certificado en un formato conocido, o no es el tipo de certificado que se esperaba."""


class CertificateNotFound(Exception):
    """No hay un certificado con ese id en la fuente. La API lo devuelve como 404."""


class DuplicateCertificate(Exception):
    """Todos los certificados recibidos ya estaban en la fuente. La API lo devuelve como 409.

    `args[0]` es la lista de ids de los que ya estaban.
    """
