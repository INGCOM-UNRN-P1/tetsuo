"""Modo pista (`--pista` o `P1_PISTA=1`): qué violación hubo y en qué función, sin la línea ni la corrección.

Revisión 05 §3: en una evaluación, tetsuo mostraba siempre la línea culpable y la acción correctiva. En
modo pista cada diagnóstico conserva el tipo de violación, su explicación y la función donde ocurrió, y
oculta la línea, la sugerencia, el fragmento del reporte y la salida cruda del sanitizer (que trae la
pila completa con números de línea). La misma variable activa el modo en daedalus y hal, y ripley la
exporta a los satélites cuando la práctica lo pide (`[general] pistas = true` en ripley.toml).
"""

from __future__ import annotations

import os

from tetsuo.core.models import SanitizerReport

VARIABLE_PISTA = "P1_PISTA"


def pista_activa(bandera: bool = False) -> bool:
    return bandera or os.environ.get(VARIABLE_PISTA, "").strip().lower() in ("1", "true", "si", "sí", "yes")


def reporte_en_pista(reporte: SanitizerReport) -> SanitizerReport:
    diagnosticos = [d.model_copy(update={"line_number": None, "suggestion_es": "", "raw_snippet": ""})
                    for d in reporte.diagnoses]
    # Si no se pudo instrumentar (falta libasan), la salida cruda explica el problema del entorno, no
    # del código: esa se conserva.
    salida = reporte.raw_output if not reporte.instrumented else ""
    return reporte.model_copy(update={"diagnoses": diagnosticos, "raw_output": salida, "pista": True})
