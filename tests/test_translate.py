"""`tetsuo translate`: el informe de un programa que ya corrió con sanitizers (Ola 7).

jonesy corre el programa del alumno instrumentado en su terminal (para que pueda escribirle la
entrada) y le pasa a tetsuo lo que imprimió: el resultado es el mismo JSON que `tetsuo run`, con
el archivo relativo al directorio de trabajo y la explicación de cada violación.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from tetsuo.cli import app

runner = CliRunner()


def _informe(raiz) -> str:
    return f"""ingresá un número: 3
=================================================================
==5150==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000020 at pc 0x55d4 bp 0x7ffd sp 0x7ffc
WRITE of size 4 at 0x502000000020 thread T0
    #0 0x55d4c0a1b2c3 in cargar {raiz}/tp/ej1/main.c:9
    #1 0x55d4c0a1b3d4 in main {raiz}/tp/ej1/main.c:15
    #2 0x7f2a1b029d8f  (/lib64/libc.so.6+0x29d8f)

0x502000000020 is located 0 bytes after 16-byte region [0x502000000010,0x502000000020)
allocated by thread T0 here:
    #0 0x7f2a1b4fd9c7 in malloc (/lib64/libasan.so.8+0xfd9c7)
    #1 0x55d4c0a1b2a1 in cargar {raiz}/tp/ej1/main.c:7

SUMMARY: AddressSanitizer: heap-buffer-overflow {raiz}/tp/ej1/main.c:9 in cargar
==5150==ABORTING
"""


def test_traduce_el_informe_con_archivo_relativo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    salida = tmp_path / "salida.txt"
    salida.write_text(_informe(tmp_path), encoding="utf-8")
    r = runner.invoke(app, ["translate", str(salida), "--json"])
    assert r.exit_code == 1
    datos = json.loads(r.stdout)
    assert not datos["passed"] and datos["diagnoses"][0]["error_tag"] == "heap-buffer-overflow"
    (h,) = datos["hallazgos"]
    assert (h["archivo"], h["linea"]) == ("tp/ej1/main.c", 9)
    assert h["id"] == "tetsuo:heap-buffer-overflow" and h["explicacion"]
    try:
        from yutani.hallazgos import validar_salida  # type: ignore[attr-defined]
    except ImportError:  # yutani anterior a 3fb723d
        return
    assert validar_salida(datos, tmp_path) == []


def test_desde_stdin_y_sin_informe():
    r = runner.invoke(app, ["translate", "--json"], input="hola\n[proceso terminado con código 0]\n")
    assert r.exit_code == 0
    datos = json.loads(r.stdout)
    assert datos["passed"] and datos["hallazgos"] == []


def test_texto_legible(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r = runner.invoke(app, ["translate"], input=_informe(tmp_path))
    assert r.exit_code == 1 and "main.c:9" in r.stdout
