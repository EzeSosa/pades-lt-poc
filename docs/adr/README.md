# Decisiones de arquitectura (ADR)

Cada decisión de arquitectura que cuesta revertir queda registrada acá: el contexto en el que se tomó, qué se decidió, qué alternativas se descartaron y qué consecuencias tiene. Un ADR no se edita después de aceptado, salvo para corregir errores o agregar links: si la decisión cambia, se escribe uno nuevo que lo **reemplaza** y el viejo pasa a estado *Reemplazado por ADR-NNNN*.

| ADR | Título | Estado |
|-----|--------|--------|
| [0001](0001-arquitectura-hexagonal.md) | Arquitectura hexagonal para las operaciones de negocio | Aceptado |
| [0002](0002-certificado-de-dominio-sobre-der.md) | El certificado de dominio se construye sobre el DER | Aceptado |
| [0003](0003-testbed-fuera-del-nucleo.md) | La PKI, el OCSP y la TSA de la PoC son un testbed fuera del núcleo | Aceptado |

## Formato

Archivo `NNNN-titulo-en-kebab-case.md`, numerado en orden, con estas secciones:

- **Estado**: Propuesto, Aceptado, Reemplazado por ADR-NNNN o Descartado, con la fecha.
- **Contexto**: el problema y las fuerzas en juego, con referencias al código.
- **Decisión**: qué se hace, en presente y sin ambigüedad.
- **Alternativas descartadas**: cada una con el motivo.
- **Consecuencias**: lo que se gana, lo que cuesta y lo que queda pendiente.
