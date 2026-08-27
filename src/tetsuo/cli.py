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


@app.command()
def run(
    target: Path = typer.Argument(..., help="Archivo .c o binario a ejecutar bajo sanitizers", exists=True),
    input_data: str = typer.Option("", "--input", "-i", help="Entrada estándar (stdin) para la ejecución"),
    json_output: bool = typer.Option(False, "--json", help="Emitir salida en formato JSON estructurado")
):
    """Compila y ejecuta con AddressSanitizer/UBSan traduciendo cualquier violación a español didáctico."""
    report = run_with_sanitizers(target, input_data=input_data)

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


@app.command()
def version():
    """Muestra la versión de TETSUO."""
    from tetsuo import __version__
    console.print(f"[bold cyan]TETSUO[/bold cyan] versión [green]{__version__}[/green]")


if __name__ == "__main__":
    app()
