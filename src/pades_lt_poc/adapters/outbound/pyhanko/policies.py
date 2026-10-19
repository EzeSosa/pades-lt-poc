"""Las políticas de pyHanko que la PoC ajusta: algoritmos (SHA-1 heredado) y análisis de modificaciones."""

from __future__ import annotations

from asn1crypto import x509 as asn1_x509
from pyhanko.sign.diff_analysis import DEFAULT_DIFF_POLICY, StandardDiffPolicy, SuspiciousModification
from pyhanko_certvalidator.policy_decl import DEFAULT_WEAK_HASH_ALGOS, DisallowWeakAlgorithmsPolicy

from ....domain.verification import DiffPolicyMode


class LegacyRootsPolicy(DisallowWeakAlgorithmsPolicy):
    """Rechaza SHA-1 como pyHanko, salvo en lo que firman las claves de `roots` (regla V-02).

    La AC Raíz de Argentina de 2007 firma con SHA-1 a sus CAs y a su CRL. Se lo
    acepta sólo para la clave de las raíces que nacieron con SHA-1: los firmantes,
    las TSAs y las demás CAs siguen sin poder usarlo.
    """

    def __init__(self, roots: list[asn1_x509.Certificate]) -> None:
        super().__init__()
        self._legacy_keys = {r.public_key.dump() for r in roots}
        self._legacy = DisallowWeakAlgorithmsPolicy(weak_hash_algos=DEFAULT_WEAK_HASH_ALGOS - {"sha1"})

    def signature_algorithm_allowed(self, algo, moment, public_key):
        if public_key is not None and public_key.dump() in self._legacy_keys:
            return self._legacy.signature_algorithm_allowed(algo, moment, public_key)
        return super().signature_algorithm_allowed(algo, moment, public_key)


class UnallocatedFreesPolicy(StandardDiffPolicy):
    """La política por defecto de pyHanko, salvo que acepta entradas libres de objetos que nunca existieron.

    iText marca a veces un número de objeto reservado y nunca escrito como `65535 f`
    (muerto para siempre). pyHanko lo trata como si se borrara un objeto, pero un
    número >= al /Size de la revisión anterior no pudo haber existido: no se borra nada.
    Liberar un objeto que sí existía sigue siendo sospechoso.
    """

    def __init__(self) -> None:
        d = DEFAULT_DIFF_POLICY
        super().__init__(d.global_rules, d.form_rule, reject_object_freeing=False)

    def apply(self, old, new, field_mdp_spec=None, doc_mdp=None):
        prev_size = new.reader.trailer.flatten(new.revision - 1)["/Size"]
        freed = {ref for ref in new.refs_freed_in_revision() if ref.idnum < prev_size}
        if freed:
            raise SuspiciousModification(
                f"The refs {freed} were freed in the revision provided. "
                "The configured difference analysis policy does not allow object freeing."
            )
        return super().apply(old, new, field_mdp_spec, doc_mdp)


DIFF_POLICIES = {
    DiffPolicyMode.DEFAULT: DEFAULT_DIFF_POLICY,
    DiffPolicyMode.ALLOW_UNALLOCATED_FREE_ENTRIES: UnallocatedFreesPolicy(),
}
