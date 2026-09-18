"""Regresión de TETSUO-D0302/D0303.

D0302: se compilaba solo con `-fsanitize=address`, así que UBSan nunca
instrumentaba el fuente: un overflow con signo daba "Ejecución Limpia".
D0303: ASan en Linux activa LeakSanitizer por defecto y su cabecera
(`ERROR: LeakSanitizer`) no coincide con la de AddressSanitizer, así que la
fuga de memoria —el error más común del curso— llegaba sin traducir. Además
se declaraban MSan, ThreadSanitizer y Valgrind Memcheck sin implementarlos.

Las salidas de los sanitizers son textos reales de sus runtimes; el flujo
compilar→ejecutar no se ejercita acá porque requiere libasan/libubsan del host.
"""

from pathlib import Path

from tetsuo.core import translator
from tetsuo.core.models import SanitizerType
from tetsuo.core.sanitizer_parser import parse_sanitizer_output

FUGA = """
=================================================================
==4242==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 64 byte(s) in 1 object(s) allocated from:
    #0 0x7f1a2b3c4d5e in malloc (/usr/lib64/libasan.so.8+0xdeadb)
    #1 0x5581a2b3c123 in main /tmp/tet_leak.c:2
    #2 0x7f1a2a029d8f  (/lib64/libc.so.6+0x29d8f)

SUMMARY: AddressSanitizer: 64 byte(s) leaked in 1 allocation(s).
"""

OVERFLOW = (
    "/tmp/ub.c:3:60: runtime error: signed integer overflow: "
    "2147483647 + 1 cannot be represented in type 'int'\n"
)


def test_la_fuga_de_memoria_se_traduce():
    diagnosticos = parse_sanitizer_output(FUGA)
    assert len(diagnosticos) == 1
    d = diagnosticos[0]
    assert d.sanitizer_type == SanitizerType.LSAN
    assert d.error_tag == "memory-leak"
    assert "64 byte(s)" in d.explanation_es


def test_la_fuga_apunta_al_fuente_del_estudiante_y_no_a_malloc():
    """El frame #0 es `malloc` dentro de libasan; el útil es el de `main`."""
    d = parse_sanitizer_output(FUGA)[0]
    assert d.function_name == "main"
    assert d.file_path == "/tmp/ub.c".replace("ub", "tet_leak")
    assert d.line_number == 2


def test_el_overflow_con_signo_se_traduce_como_ubsan():
    diagnosticos = parse_sanitizer_output(OVERFLOW)
    assert [d.sanitizer_type for d in diagnosticos] == [SanitizerType.UBSAN]


def test_una_salida_limpia_no_produce_diagnosticos():
    assert parse_sanitizer_output("hola mundo\n") == []


def test_se_compila_con_address_y_undefined(monkeypatch, tmp_path):
    """Sin `undefined` UBSan no instrumenta y el overflow pasaba como limpio."""
    flags_vistas = []

    def falso_daedalus(source_c, bin_path):
        return None  # fuerza la vía de respaldo con gcc

    class Res:
        returncode = 1
        stderr = "sin toolchain"
        stdout = ""

    def falso_run(cmd, *a, **k):
        flags_vistas.append(list(cmd))
        return Res()

    monkeypatch.setattr(translator, "_compilar_con_daedalus", falso_daedalus)
    monkeypatch.setattr(translator.subprocess, "run", falso_run)

    fuente = tmp_path / "x.c"
    fuente.write_text("int main(void){return 0;}\n", encoding="utf-8")
    translator.run_with_sanitizers(fuente)

    compilaciones = [c for c in flags_vistas if any(a.startswith("-fsanitize") for a in c)]
    assert compilaciones, "no se intentó compilar con sanitizers"
    assert all("-fsanitize=address,undefined" in c for c in compilaciones)


def test_la_via_daedalus_tambien_pide_undefined():
    fuente = Path(translator.__file__).read_text(encoding="utf-8")
    assert '"-fsanitize=address"' not in fuente
    assert fuente.count("-fsanitize=address,undefined") >= 2


def test_no_se_declaran_capacidades_inexistentes():
    raiz = Path(__file__).resolve().parents[1]
    texto = (raiz / "pyproject.toml").read_text(encoding="utf-8") + (raiz / "README.md").read_text(encoding="utf-8")
    assert "MSan" not in texto
    assert "traducción de reportes de fallos de memoria emitidos por Valgrind" not in texto
