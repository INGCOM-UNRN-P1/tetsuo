"""Regresión de TETSUO-D0601/D0903: JSON versionado y observaciones canónicas."""

import json

from typer.testing import CliRunner

from tetsuo.cli import app
from tetsuo.core.models import SanitizerDiagnosis, SanitizerReport, SanitizerType

runner = CliRunner()


def _reporte_con_fallo():
    d = SanitizerDiagnosis(
        sanitizer_type=SanitizerType.ASAN, error_tag="heap-buffer-overflow",
        title_es="Desbordamiento", explanation_es="x", suggestion_es="y",
        file_path="a.c", line_number=7,
    )
    return SanitizerReport(binary_or_source="a.c", passed=False, diagnoses=[d])


def test_contrato_versionado_con_instrumentacion_y_observaciones():
    data = _reporte_con_fallo().to_contract()
    assert data["schema_version"] == "1.0.0"
    assert data["instrumented"] is True
    assert data["ok"] is False
    obs = data["observaciones"][0]
    assert obs["rule_code"] == "TET-heap-buffer-overflow"
    assert (obs["file"], obs["line"], obs["source_plugin"]) == ("a.c", 7, "tetsuo")


def test_cli_json_incluye_schema_version_y_observaciones(tmp_path):
    src = tmp_path / "a.c"
    src.write_text("int main(void){return 0;}", encoding="utf-8")
    res = runner.invoke(app, ["run", str(src), "--json"])
    data = json.loads(res.output)
    assert data["schema_version"] == "1.0.0"
    assert "observaciones" in data and "instrumented" in data


def test_version_como_opcion_global():
    """TETSUO-D0402."""
    from tetsuo import __version__
    for flag in ("--version", "-v"):
        res = runner.invoke(app, [flag])
        assert res.exit_code == 0 and __version__ in res.output
