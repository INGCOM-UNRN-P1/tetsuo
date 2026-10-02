"""stack-use-after-scope, SEGV y UBSan específicos (QoL #958, #965), sin libasan y taxonomía."""

import shutil

import pytest

from tetsuo.core.models import SanitizerReport
from tetsuo.core.sanitizer_parser import parse_sanitizer_output
from tetsuo.core.translator import explicar_error_de_compilacion, run_with_sanitizers

con_asan = pytest.mark.skipif(shutil.which("gcc") is None, reason="hace falta gcc con libasan")


def test_stack_use_after_scope():
    (d,) = parse_sanitizer_output(
        "==1==ERROR: AddressSanitizer: stack-use-after-scope on address 0x7ffd1 at pc 0x4011 bp 0x7ff sp 0x7f\n"
        "READ of size 4 at 0x7ffd1 thread T0\n    #0 0x4011 in main /tmp/a.c:9\n")
    assert d.error_tag == "stack-use-after-scope" and "bloque" in d.title_es.lower() and d.line_number == 9


def test_segv_de_asan():
    (d,) = parse_sanitizer_output("==7==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x1)\n"
                                  "    #0 0x1 in cargar /tmp/tp.c:12\n")
    assert d.error_tag == "segv" and d.line_number == 12


@pytest.mark.parametrize("mensaje, tag", [
    ("signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'", "signed-integer-overflow"),
    ("division by zero", "division-by-zero"),
    ("shift exponent 40 is too large for 32-bit type 'int'", "shift-out-of-bounds"),
    ("index 10 out of bounds for type 'int [10]'", "array-index-out-of-bounds"),
    ("load of null pointer of type 'int'", "null-pointer"),
])
def test_ubsan_especifico(mensaje, tag):
    (d,) = parse_sanitizer_output(f"/tmp/t.c:5:13: runtime error: {mensaje}\n")
    assert d.error_tag == tag and d.file_path == "/tmp/t.c" and d.line_number == 5


def test_sin_libasan_explica_alternativas():
    texto = explicar_error_de_compilacion("/usr/bin/ld: cannot find -lasan: No such file or directory")
    assert "WSL" in texto and "hal check" in texto
    assert explicar_error_de_compilacion("t.c:1:1: error: x").startswith("Error de compilación")


def test_hallazgos_en_la_taxonomia_comun():
    diags = parse_sanitizer_output("/tmp/t.c:5:13: runtime error: division by zero\n")
    datos = SanitizerReport(binary_or_source="t.c", passed=False, diagnoses=diags).to_contract()
    (h,) = datos["hallazgos"]
    assert h["id"] == "tetsuo:division-by-zero" and h["categoria"] == "numeros"


@con_asan
def test_overflow_real(tmp_path):
    fuente = tmp_path / "o.c"
    fuente.write_text("#include <limits.h>\nint main(void)\n{\n    volatile int x = INT_MAX;\n    x = x + 1;\n"
                      "    return 0;\n}\n", encoding="utf-8")
    rep = run_with_sanitizers(fuente)
    if not rep.instrumented and "libasan" in rep.raw_output:
        pytest.skip("este gcc no trae libasan")
    assert any(d.error_tag == "signed-integer-overflow" for d in rep.diagnoses)
