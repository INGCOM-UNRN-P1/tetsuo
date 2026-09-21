"""Plugin de TETSUO para el microkernel RIPLEY."""

from pathlib import Path
from typing import Dict, Any
from tetsuo.core.translator import run_with_sanitizers


class TetsuoPlugin:
    """Plugin de traducción de sanitizers para Ripley."""

    name = "sanitizer_translator"
    description = "Traducción pedagógica de reportes de AddressSanitizer y UndefinedBehaviorSanitizer a español"

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        source_dir = Path(context.get("source_dir", "."))
        main_c = source_dir / "main.c"
        if not main_c.exists():
            return {"passed": True, "diagnoses_count": 0}

        report = run_with_sanitizers(main_c)

        return {
            "schema_version": report.schema_version,
            "ok": report.passed,
            "instrumented": report.instrumented,
            "observaciones": report.observaciones(),
            "passed": report.passed,
            "diagnoses_count": len(report.diagnoses),
            "diagnoses": [
                {
                    "type": d.sanitizer_type,
                    "title": d.title_es,
                    "explanation": d.explanation_es,
                    "suggestion": d.suggestion_es,
                    "location": f"{d.file_path}:{d.line_number}" if d.file_path else "N/A"
                }
                for d in report.diagnoses
            ]
        }
