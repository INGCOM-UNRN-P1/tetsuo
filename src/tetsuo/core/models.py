"""Modelos de datos para el diagnóstico de sanitizers en TETSUO."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class SanitizerType(str, Enum):
    ASAN = "AddressSanitizer"
    UBSAN = "UndefinedBehaviorSanitizer"
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
    binary_or_source: str
    passed: bool = True
    diagnoses: List[SanitizerDiagnosis] = Field(default_factory=list)
    raw_output: str = ""
