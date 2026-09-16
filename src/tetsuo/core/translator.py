"""Compilador y ejecutor de binarios bajo sanitizers."""

import tempfile
import subprocess
from pathlib import Path
from typing import List, Optional
from tetsuo.core.models import SanitizerReport
from tetsuo.core.sanitizer_parser import parse_sanitizer_output


def _compilar_con_daedalus(source_c: Path, bin_path: Path) -> Optional[tuple[bool, str]]:
    try:
        from daedalus.core.compiler import compilar_archivos
        res = compilar_archivos([source_c], binario_salida=bin_path, flags_adicionales=["-fsanitize=address", "-O0", "-g"])
        return res.exito, res.stderr_crudo
    except ImportError:
        import sys
        sibling = Path(__file__).resolve().parents[4] / "daedalus" / "src"
        if sibling.is_dir() and str(sibling) not in sys.path:
            sys.path.insert(0, str(sibling))
            try:
                from daedalus.core.compiler import compilar_archivos
                res = compilar_archivos([source_c], binario_salida=bin_path, flags_adicionales=["-fsanitize=address", "-O0", "-g"])
                return res.exito, res.stderr_crudo
            except ImportError:
                return None
def _try_import_nostromo():
    try:
        from nostromo.core.sandbox import ejecutar_aislado
        return ejecutar_aislado
    except ImportError:
        import sys
        sibling = Path(__file__).resolve().parents[4] / "nostromo" / "src"
        if sibling.is_dir() and str(sibling) not in sys.path:
            sys.path.insert(0, str(sibling))
            try:
                from nostromo.core.sandbox import ejecutar_aislado
                return ejecutar_aislado
            except ImportError:
                return None
        return None


def run_with_sanitizers(source_or_binary: Path, input_data: str = "") -> SanitizerReport:
    """Compila (si es .c) con sanitizers y ejecuta capturando diagnósticos."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        if source_or_binary.suffix == ".c":
            bin_path = tmp_path / "app_sanitized"
            daed_res = _compilar_con_daedalus(source_or_binary, bin_path)
            if daed_res is not None:
                ok, stderr = daed_res
                if not ok:
                    return SanitizerReport(
                        binary_or_source=str(source_or_binary),
                        target_file=str(source_or_binary),
                        instrumented=False,
                        passed=False,
                        diagnoses=[],
                        raw_output=f"Error de compilación bajo sanitizers (-fsanitize=address):\n{stderr}"
                    )
            else:
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

        # Ejecutar de forma aislada vía nostromo (con fallback)
        nostromo_fn = _try_import_nostromo()
        if nostromo_fn:
            res_aislado = nostromo_fn(target_bin, stdin_texto=input_data, timeout_segundos=5.0, memoria_mb=256, usar_bwrap=True)
            if res_aislado.error_tipo == "TIMEOUT":
                return SanitizerReport(
                    binary_or_source=str(source_or_binary),
                    target_file=str(source_or_binary),
                    instrumented=True,
                    passed=False,
                    diagnoses=[],
                    raw_output="Timeout excedido durante la ejecución."
                )
            raw_err = res_aislado.stderr + "\n" + res_aislado.stdout
            diagnoses = parse_sanitizer_output(raw_err)
            passed = (res_aislado.codigo_retorno == 0 and len(diagnoses) == 0)

            return SanitizerReport(
                binary_or_source=str(source_or_binary),
                target_file=str(source_or_binary),
                instrumented=True,
                passed=passed,
                diagnoses=diagnoses,
                raw_output=raw_err
            )

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
