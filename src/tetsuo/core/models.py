"""Modelos de datos para el diagnóstico de sanitizers en TETSUO."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class SanitizerType(str, Enum):
    ASAN = "AddressSanitizer"
    UBSAN = "UndefinedBehaviorSanitizer"
    LSAN = "LeakSanitizer"
    MSAN = "MemorySanitizer"
    TSAN = "ThreadSanitizer"
    UNKNOWN = "Unknown"


class SanitizerDiagnosis(BaseModel):
    sanitizer_type: SanitizerType
    error_tag: str  # "heap-buffer-overflow", "stack-buffer-overflow", "use-after-free", "signed-integer-overflow"
    title_es: str
    explanation_es: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    function_name: Optional[str] = None
    memory_address: Optional[str] = None
    access_type: Optional[str] = None  # "READ", "WRITE"
    suggestion_es: str
    raw_snippet: str = ""


class SanitizerReport(BaseModel):
    schema_version: str = "1.0.0"
    binary_or_source: str
    target_file: Optional[str] = None
    instrumented: bool = True
    passed: bool = True
    diagnoses: List[SanitizerDiagnosis] = Field(default_factory=list)
    raw_output: str = ""
    pista: bool = False  # modo pista: sin líneas ni sugerencias (ver core/pista.py)

    def __init__(self, **data):
        if "binary_or_source" in data and not data.get("target_file"):
            data["target_file"] = data["binary_or_source"]
        super().__init__(**data)

    def observaciones(self) -> List[dict]:
        """Diagnósticos en la forma canónica de observaciones de los satélites."""
        return [
            {
                "rule_code": f"TET-{d.error_tag}",
                "severity": "error",
                "file": d.file_path or "",
                "line": d.line_number or 0,
                "message": d.title_es,
                "suggestion": d.suggestion_es,
                "source_plugin": "tetsuo",
            }
            for d in self.diagnoses
        ]

    def to_contract(self) -> dict:
        """JSON versionado: modelo completo + `ok` y `observaciones` canónicos.

        `instrumented` distingue "limpio instrumentado" de "no se pudo
        instrumentar" (en ese caso `passed` no significa memoria limpia).
        """
        data = self.model_dump()
        data["ok"] = self.passed
        data["observaciones"] = self.observaciones()
        data["hallazgos"] = self.hallazgos()
        return data

    def hallazgos(self) -> List[dict]:
        """Diagnósticos en la taxonomía común del ecosistema (yutani.hallazgos)."""
        import yutani.hallazgos as taxonomia
        return [
            taxonomia.hallazgo("tetsuo", d.error_tag, CATEGORIA_POR_TAG.get(d.error_tag, "memoria"), "error", d.title_es,
                     archivo=d.file_path, linea=d.line_number, sugerencia=d.suggestion_es or None)
            for d in self.diagnoses
        ]


CATEGORIA_POR_TAG = {
    "heap-buffer-overflow": "arreglos", "stack-buffer-overflow": "arreglos", "global-buffer-overflow": "arreglos",
    "array-index-out-of-bounds": "arreglos",
    "heap-use-after-free": "memoria", "double-free": "memoria", "bad-free": "memoria",
    "alloc-dealloc-mismatch": "memoria", "memory-leak": "memoria",
    "stack-use-after-return": "punteros", "stack-use-after-scope": "punteros", "segv": "punteros",
    "null-pointer": "punteros", "misaligned": "punteros",
    "signed-integer-overflow": "numeros", "shift-out-of-bounds": "numeros", "conversion": "numeros",
    "division-by-zero": "numeros", "undefined-behavior": "numeros",
}
