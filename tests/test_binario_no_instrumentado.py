"""Un binario sin sanitizers no puede declararse «limpio» (N-TETSUO-01).

`tetsuo run ./programa` ejecutaba cualquier binario y, si terminaba bien,
informaba «Ejecución limpia sin errores de sanitizers», aunque el binario no
tuviera instrumentación: un desborde de heap real pasaba como limpio.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from tetsuo.core.translator import binario_instrumentado, run_with_sanitizers

DESBORDE = """#include <stdlib.h>
#include <stdio.h>
int main(void)
{
    int *v = malloc(4 * sizeof(int));
    v[4] = 7;
    printf("%d\\n", v[4]);
    free(v);
    return 0;
}
"""


def test_detecta_marcas_de_instrumentacion(tmp_path: Path):
    sin = tmp_path / "sin"
    sin.write_bytes(b"\\x7fELF...main...printf")
    con = tmp_path / "con"
    con.write_bytes(b"\\x7fELF...__asan_init...main")
    assert binario_instrumentado(sin) is False
    assert binario_instrumentado(con) is True


@pytest.mark.skipif(not shutil.which("gcc"), reason="requiere gcc")
def test_binario_sin_sanitizers_no_se_declara_limpio(tmp_path: Path):
    fuente = tmp_path / "desborde.c"
    fuente.write_text(DESBORDE)
    binario = tmp_path / "desborde"
    subprocess.run(["gcc", "-o", str(binario), str(fuente)], check=True)

    reporte = run_with_sanitizers(binario)
    assert reporte.passed is False
    assert reporte.instrumented is False
    assert "no está instrumentado" in reporte.raw_output
