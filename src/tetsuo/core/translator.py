"""Compilador y ejecutor de binarios bajo sanitizers."""

import tempfile
import subprocess
from pathlib import Path
from typing import List, Optional
from tetsuo.core.models import SanitizerReport
from tetsuo.core.sanitizer_parser import parse_sanitizer_output


def run_with_sanitizers(source_or_binary: Path, input_data: str = "") -> SanitizerReport:
    """Compila (si es .c) con sanitizers y ejecuta capturando diagnósticos."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        if source_or_binary.suffix == ".c":
            bin_path = tmp_path / "app_sanitized"
            # Intentar compilar con sanitizers
            comp = subprocess.run(
                ["gcc", "-O0", "-g", "-fsanitize=address", str(source_or_binary), "-o", str(bin_path)],
                capture_output=True,
                text=True,
                check=False
            )
            if comp.returncode != 0:
                return SanitizerReport(
                    binary_or_source=str(source_or_binary),
                    target_file=str(source_or_binary),
                    instrumented=False,
                    passed=False,
                    diagnoses=[],
                    raw_output=f"Error de compilación bajo sanitizers (-fsanitize=address):\n{comp.stderr}"
                )
            target_bin = bin_path
        else:
            target_bin = source_or_binary

        # Ejecutar
        try:
            res = subprocess.run(
                [str(target_bin)],
                input=input_data,
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )
            raw_err = res.stderr + "\n" + res.stdout
            diagnoses = parse_sanitizer_output(raw_err)
            passed = (res.returncode == 0 and len(diagnoses) == 0)

            return SanitizerReport(
                binary_or_source=str(source_or_binary),
                target_file=str(source_or_binary),
                instrumented=True,
                passed=passed,
                diagnoses=diagnoses,
                raw_output=raw_err
            )
        except subprocess.TimeoutExpired:
            return SanitizerReport(
                binary_or_source=str(source_or_binary),
                target_file=str(source_or_binary),
                instrumented=True,
                passed=False,
                diagnoses=[],
                raw_output="Timeout excedido durante la ejecución."
            )
