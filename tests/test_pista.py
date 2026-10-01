"""Modo pista (`--pista` o P1_PISTA=1): la violación y la función, sin la línea ni la corrección."""

import json

from typer.testing import CliRunner

import tetsuo.cli as cli
from tetsuo.core.models import SanitizerDiagnosis, SanitizerReport, SanitizerType
from tetsuo.core.pista import pista_activa, reporte_en_pista

runner = CliRunner()


def _reporte(instrumentado: bool = True) -> SanitizerReport:
    diagnostico = SanitizerDiagnosis(
        sanitizer_type=SanitizerType.ASAN, error_tag="heap-buffer-overflow",
        title_es="Desbordamiento de búfer en el heap",
        explanation_es="Se leyó una posición fuera del bloque pedido con malloc.",
        file_path="heap.c", line_number=5, function_name="leer", memory_address="0x602000000020",
        access_type="READ", suggestion_es="El índice válido va de 0 a n - 1: usá v[n - 1].",
        raw_snippet="READ of size 4 at 0x602000000020 … #0 leer heap.c:5")
    return SanitizerReport(binary_or_source="heap.c", passed=False, instrumented=instrumentado,
                           diagnoses=[diagnostico], raw_output="==1==ERROR: … heap.c:5")


def test_reporte_en_pista():
    pista = reporte_en_pista(_reporte())
    d = pista.diagnoses[0]
    assert pista.pista and pista.raw_output == ""
    assert d.line_number is None and d.suggestion_es == "" and d.raw_snippet == ""
    assert d.function_name == "leer" and d.title_es and d.explanation_es
    assert pista.observaciones()[0]["line"] == 0 and pista.observaciones()[0]["suggestion"] == ""
    # Sin instrumentar (falta libasan) la salida cruda es del entorno y se conserva.
    assert reporte_en_pista(_reporte(instrumentado=False)).raw_output


def test_cli_en_modo_pista(tmp_path, monkeypatch):
    fuente = tmp_path / "heap.c"
    fuente.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    monkeypatch.setattr(cli, "run_with_sanitizers", lambda *a, **k: _reporte())
    monkeypatch.delenv("P1_PISTA", raising=False)
    assert not pista_activa()
    res = runner.invoke(cli.app, ["check", str(fuente), "--json", "--pista"])
    datos = json.loads(res.stdout)
    assert res.exit_code == 1 and datos["pista"] is True and datos["diagnoses"][0]["line_number"] is None

    monkeypatch.setenv("P1_PISTA", "1")
    res = runner.invoke(cli.app, ["check", str(fuente)], env={"COLUMNS": "300"})
    assert "heap.c, en la función leer()" in res.output and "heap.c:5" not in res.output
    assert "Acción Correctiva" not in res.output and "Modo pista" in res.output
