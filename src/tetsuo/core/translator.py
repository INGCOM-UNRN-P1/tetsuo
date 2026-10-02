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
    except ImportError:
        return None  # sin el extra `ecosistema` se usa el camino propio
    res = compilar_archivos([source_c], binario_salida=bin_path, flags_adicionales=["-fsanitize=address,undefined", "-O0", "-g"])
    return res.exito, res.stderr_crudo


def _try_import_nostromo():
    try:
        from nostromo.core.sandbox import ejecutar_aislado
    except ImportError:
        return None  # sin el extra `ecosistema` se usa el camino propio
    return ejecutar_aislado


_SIN_SANITIZERS = ("cannot find -lasan", "cannot find -lubsan", "libasan", "libubsan",
                   "unsupported option '-fsanitize", "-fsanitize=address' is not supported",
                   "unrecognized command-line option '-fsanitize")


def explicar_error_de_compilacion(stderr: str) -> str:
    """Si el compilador no trae los sanitizers (MinGW en Windows, Linux sin libasan), dice qué hacer en
    lugar de mostrar solo el error del enlazador."""
    if any(marca in stderr for marca in _SIN_SANITIZERS):
        return (
            "Error de compilación bajo sanitizers: este compilador no trae AddressSanitizer/UBSan (pasa con MinGW/MSYS2 en Windows y en Linux sin "
            "libasan), así que tetsuo no puede instrumentar el programa. Alternativas:\n"
            "• en Linux, instalá libasan (Debian/Ubuntu: `sudo apt install libasan8 libubsan1`; "
            "Fedora: `sudo dnf install libasan libubsan`);\n"
            "• en Windows, usá WSL con el entorno de la cátedra en modo Linux;\n"
            "• mientras tanto, `hal check programa.c` diagnostica los crashes y `hal valgrind` traduce un "
            "informe de Valgrind.\n\n"
            f"Salida del compilador:\n{stderr}"
        )
    return f"Error de compilación bajo sanitizers (-fsanitize=address,undefined):\n{stderr}"


# Símbolos que deja la instrumentación de ASan/UBSan/TSan en el ejecutable.
_MARCAS_INSTRUMENTACION = (b"__asan_init", b"__ubsan_handle", b"__tsan_init")


def binario_instrumentado(binario: Path) -> bool:
    """True si el ejecutable fue compilado con algún sanitizer.

    Un binario sin instrumentación corre sin que ASan/UBSan observen nada:
    que termine bien no dice nada sobre desbordes o use-after-free.
    """
    try:
        contenido = binario.read_bytes()
    except OSError:
        return False
    return any(marca in contenido for marca in _MARCAS_INSTRUMENTACION)


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
                        raw_output=explicar_error_de_compilacion(stderr)
                    )
            else:
                comp = subprocess.run(
                    ["gcc", "-O0", "-g", "-fsanitize=address,undefined", str(source_or_binary), "-o", str(bin_path)],
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
                        raw_output=explicar_error_de_compilacion(comp.stderr)
                    )
            target_bin = bin_path
        else:
            target_bin = source_or_binary
            if not binario_instrumentado(target_bin):
                # N-TETSUO-01: antes se ejecutaba igual y, al terminar sin
                # errores, se informaba «Ejecución limpia sin errores de
                # sanitizers» aunque ningún sanitizer estuviera activo.
                return SanitizerReport(
                    binary_or_source=str(source_or_binary),
                    target_file=str(source_or_binary),
                    instrumented=False,
                    passed=False,
                    diagnoses=[],
                    raw_output=(
                        f"El binario {source_or_binary.name} no está instrumentado con sanitizers: "
                        "ASan/UBSan no pueden observar su ejecución, así que no se puede afirmar que "
                        "esté libre de desbordes o use-after-free. Compilalo con "
                        "-fsanitize=address,undefined -g o pasale a tetsuo el archivo .c."
                    ),
                )

        # Ejecutar de forma aislada vía nostromo (con fallback)
        nostromo_fn = _try_import_nostromo()
        if nostromo_fn:
            res_aislado = nostromo_fn(target_bin, stdin_texto=input_data, timeout_segundos=5.0, memoria_mb=0, usar_bwrap=True)
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
