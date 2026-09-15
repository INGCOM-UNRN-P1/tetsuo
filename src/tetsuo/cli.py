"""CLI principal de TETSUO."""

import json
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from tetsuo.core.models import SanitizerReport
from tetsuo.core.translator import run_with_sanitizers

app = typer.Typer(
    name="tetsuo",
    help="Traductor y explicador pedagógico de sanitizers (ASan, UBSan, MSan) en español",
    add_completion=True
)
console = Console()


def generar_seccion_markdown(report: SanitizerReport) -> str:
    """Genera sección de reporte de Sanitizers (ASan/UBSan) para Dredd."""
    lines = ["## Diagnóstico de Sanitizers y Memoria Dinámica (Tetsuo)\n"]
    lines.append(f"- **Archivo analizado:** `{Path(report.target_file).name}`")
    lines.append(f"- **Diagnósticos de sanitizers:** {len(report.diagnoses)}\n")
    if report.passed:
        lines.append("> [!TIP]\n> **Memoria Limpia:** No se detectaron violaciones de AddressSanitizer (buffer overflows, use-after-free) ni UndefinedBehaviorSanitizer.\n")
    else:
        lines.append("> [!CAUTION]\n> **Fallo de Seguridad en Memoria / Comportamiento Indefinido:**\n")
        lines.append("| Sanitizer | Ubicación | Diagnóstico | Causa Raíz / Explicación | Sugerencia |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for diag in report.diagnoses:
            loc_str = f"`{Path(diag.file_path).name}:{diag.line_number}`" if diag.file_path else "—"
            lines.append(f"| **{diag.sanitizer_type}** | {loc_str} | {diag.title_es} | {diag.explanation_es} | {diag.suggestion_es} |")
        lines.append("")
    return "\n".join(lines)


@app.command("run")
@app.command("check")
def run(
    target: Path = typer.Argument(..., help="Archivo .c o binario a ejecutar bajo sanitizers", exists=True),
    input_data: str = typer.Option("", "--input", "-i", help="Entrada estándar (stdin) para la ejecución"),
    json_output: bool = typer.Option(False, "--json", help="Emitir salida en formato JSON estructurado"),
    output_md: Optional[Path] = typer.Option(None, "--md", "--output-md", help="Generar sección de reporte en formato Markdown para fusión en Dredd."),
):
    """Compila y ejecuta con AddressSanitizer/UBSan traduciendo cualquier violación a español didáctico."""
    report = run_with_sanitizers(target, input_data=input_data)

    if output_md:
        md_text = generar_seccion_markdown(report)
        output_md.parent.mkdir(parents=True, exist_ok=True)
        output_md.write_text(md_text, encoding="utf-8")
        console.print(f"[bold green]✓ Sección Markdown generada en:[/bold green] {output_md}")
        raise typer.Exit(code=0 if report.passed else 1)

    if json_output:
        print(json.dumps(report.model_dump(), indent=2, ensure_ascii=False))
        if not report.passed:
            raise typer.Exit(code=1)
        return

    if report.passed:
        console.print(Panel(
            f"[bold green]✓ Ejecución Limpia sin Errores de Sanitizers[/bold green]\n"
            f"• Archivo: {target.name}\n"
            f"• Sin desbordamientos de búfer, use-after-free ni comportamiento indefinido.",
            title="[bold green]TETSUO Sanitizers OK[/bold green]"
        ))
        return

    if not report.diagnoses:
        console.print(Panel(
            f"[bold red]❌ Error de Compilación o Ejecución:[/bold red]\n{report.raw_output}",
            title="[bold red]TETSUO Error[/bold red]"
        ))
        raise typer.Exit(code=1)

    for diag in report.diagnoses:
        loc_str = f"{diag.file_path}:{diag.line_number} (en función {diag.function_name})" if diag.file_path else "Ubicación no identificada"
        panel_content = (
            f"[bold red]🚨 {diag.title_es}[/bold red]\n\n"
            f"• [bold]Ubicación:[/bold] {loc_str}\n"
            f"• [bold]Tipo de Acceso:[/bold] {diag.access_type or 'N/A'}\n"
            f"• [bold]Dirección de Memoria:[/bold] {diag.memory_address or 'N/A'}\n\n"
            f"[bold yellow]Explicación Didáctica:[/bold yellow]\n{diag.explanation_es}\n\n"
            f"[bold green]↳ Acción Correctiva Recomendada:[/bold green]\n{diag.suggestion_es}"
        )
        console.print(Panel(panel_content, title=f"[bold red]{diag.sanitizer_type}[/bold red]"))

    raise typer.Exit(code=1)


@app.command("report")
def report_cmd(
    target: Path = typer.Argument(..., help="Archivo .c o binario a ejecutar bajo sanitizers", exists=True),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Ruta de destino del archivo Markdown."),
    input_data: str = typer.Option("", "--input", "-i", help="Entrada estándar para la ejecución"),
):
    """Genera directamente la sección de reporte Markdown de TETSUO para Dredd."""
    report = run_with_sanitizers(target, input_data=input_data)
    md_content = generar_seccion_markdown(report)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(md_content, encoding="utf-8")
        console.print(f"[bold green]✓ Reporte Markdown generado en:[/bold green] {output}")
    else:
        print(md_content)


@app.command("doctor")
def doctor_cmd(
    json_output: bool = typer.Option(False, "--json", help="Emitir diagnóstico en formato JSON estructurado."),
) -> None:
    """Verifica el estado del entorno de sanitizers TETSUO (GCC, Clang, soporte libasan/libubsan)."""
    import shutil
    import subprocess
    import sys
    import tempfile
    diagnostico = []

    py_ok = sys.version_info >= (3, 10)
    diagnostico.append({
        "componente": "Python Runtime",
        "estado": "OK" if py_ok else "ERROR",
        "requerido": True,
        "detalle": f"Python {sys.version.split()[0]}",
    })

    gcc_path = shutil.which("gcc")
    diagnostico.append({
        "componente": "Compilador GCC",
        "estado": "OK" if gcc_path else "ERROR",
        "requerido": True,
        "detalle": gcc_path or "No encontrado (requerido para compilar con AddressSanitizer)",
    })

    # Verificar que GCC soporte -fsanitize=address
    asan_ok = False
    asan_det = ""
    if gcc_path:
        with tempfile.NamedTemporaryFile(suffix=".c", mode="w", delete=False) as f:
            f.write("int main(void) { return 0; }\n")
            c_name = f.name
        try:
            res = subprocess.run([gcc_path, "-fsanitize=address,undefined", c_name, "-o", "/dev/null"], capture_output=True, text=True)
            if res.returncode == 0:
                asan_ok = True
                asan_det = "Soporte ASan y UBSan operativo en GCC"
            else:
                asan_det = f"Falla al enlazar libasan: {res.stderr.strip()}"
        except Exception as e:
            asan_det = str(e)
        finally:
            Path(c_name).unlink(missing_ok=True)
    else:
        asan_det = "Sin compilador GCC"

    diagnostico.append({
        "componente": "AddressSanitizer (libasan)",
        "estado": "OK" if asan_ok else "ERROR",
        "requerido": True,
        "detalle": asan_det,
    })

    clang_path = shutil.which("clang")
    diagnostico.append({
        "componente": "Compilador Clang",
        "estado": "OK" if clang_path else "ADVERTENCIA",
        "requerido": False,
        "detalle": clang_path or "No encontrado (opcional, motor alternativo)",
    })

    todo_ok = py_ok and bool(gcc_path) and asan_ok

    if json_output:
        import json
        payload = {
            "schema_version": "1.0.0",
            "herramienta": "tetsuo",
            "ok": todo_ok,
            "componentes": diagnostico,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        raise typer.Exit(code=0 if todo_ok else 1)

    tabla = Table(title="🏥 Diagnóstico del Entorno TETSUO (doctor)", border_style="cyan")
    tabla.add_column("Componente", style="bold white")
    tabla.add_column("Estado", justify="center")
    tabla.add_column("Detalle")

    for c in diagnostico:
        color = "bold green" if c["estado"] == "OK" else ("bold yellow" if c["estado"] == "ADVERTENCIA" else "bold red")
        simbolo = "✓" if c["estado"] == "OK" else ("⚠️" if c["estado"] == "ADVERTENCIA" else "✗")
        tabla.add_row(c["componente"], f"[{color}]{simbolo} {c['estado']}[/{color}]", c["detalle"])

    console.print(tabla)
    if not todo_ok:
        console.print("\n[bold red]Instalá gcc y libasan (`sudo apt install gcc libasan6` o equivalente).[/bold red]")
        raise typer.Exit(code=1)


@app.command()
def version():
    """Muestra la versión de TETSUO."""
    from tetsuo import __version__
    console.print(f"[bold cyan]TETSUO[/bold cyan] versión [green]{__version__}[/green]")


if __name__ == "__main__":
    app()
