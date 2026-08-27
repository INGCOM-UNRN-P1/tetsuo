"""Tests unitarios y de integración para TETSUO."""

from pathlib import Path
from typer.testing import CliRunner
from tetsuo.cli import app
from tetsuo.core.sanitizer_parser import parse_sanitizer_output
from tetsuo.core.translator import run_with_sanitizers
from tetsuo.plugins.ripley_plugin import TetsuoPlugin

runner = CliRunner()


def test_parse_asan_heap_overflow():
    raw = """
    =================================================================
    ==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000018
    READ of size 4 at 0x602000000018 thread T0
        #0 0x55a123 in main /home/user/app.c:10
    =================================================================
    """
    diagnoses = parse_sanitizer_output(raw)
    assert len(diagnoses) == 1
    d = diagnoses[0]
    assert "Heap" in d.title_es
    assert d.line_number == 10
    assert d.function_name == "main"


def test_run_with_sanitizers_clean(tmp_path):
    c = tmp_path / "clean.c"
    c.write_text("int main(void) { return 0; }")
    report = run_with_sanitizers(c)
    assert report.passed is True
    assert len(report.diagnoses) == 0


def test_run_with_sanitizers_heap_overflow(tmp_path):
    raw_asan = """
    ==5555==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x12345
    WRITE of size 4 at 0x12345 thread T0
        #0 0x111 in main app.c:15
    """
    diagnoses = parse_sanitizer_output(raw_asan)
    assert len(diagnoses) > 0
    assert diagnoses[0].error_tag == "heap-buffer-overflow"
    assert "Heap" in diagnoses[0].title_es


def test_cli_run_clean(tmp_path):
    c = tmp_path / "main.c"
    c.write_text("int main(void) { return 0; }")
    res = runner.invoke(app, ["run", str(c), "--json"])
    assert res.exit_code == 0
    assert '"passed": true' in res.output


def test_cli_version():
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert "TETSUO" in res.output


def test_ripley_plugin(tmp_path):
    c = tmp_path / "main.c"
    c.write_text("int main(void) { return 0; }")
    plugin = TetsuoPlugin()
    res = plugin.run({"source_dir": str(tmp_path)})
    assert res["passed"] is True
