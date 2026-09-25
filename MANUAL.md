# Manual de Uso y Referencia Técnica: tetsuo

> **TETSUO** — Traductor y explicador pedagógico en español de sanitizers (ASan, UBSan, LSan)
> **Versión:** `0.1.0` · **CLI principal:** `tetsuo` · **Plugin Ripley:** `sanitizer_translator`

---

## 1. Arquitectura y Propósito Pedagógico

`tetsuo` forma parte del ecosistema de herramientas de la cátedra de Programación 1 (UNRN). Su objetivo central es resolver de forma modular, determinista y automatizada las tareas asociadas a su dominio específico dentro del ciclo de desarrollo, evaluación y aprendizaje de software en C.

### Alcance Funcional (Qué cubre)
- Compilación instrumentada, ejecución controlada y traducción pedagógica de diagnósticos de sanitizers en programas C.
- Captura y traducción contextual a español rioplatense de advertencias complejas de AddressSanitizer (ASan), UndefinedBehaviorSanitizer (UBSan) y LeakSanitizer (LSan).
- No traduce Valgrind Memcheck, MemorySanitizer ni ThreadSanitizer: solo ASan, UBSan y LSan.
- Identificación de lecturas fuera de límites, accesos tras liberación (use-after-free) y fugas de memoria con indicación precisa de línea y archivo.

### Límites de Responsabilidad y Delegación (Qué no cubre)
- Confinamiento en sandbox no privilegiado de kernel (delegado a `nostromo`).
- Depuración forense con GDB de core dumps no instrumentados: la cubre `hal`, herramienta complementaria; tetsuo no la invoca ni depende de ella.
- Inyección deliberada de fallos de memoria en runtime (delegado a `vasquez`).

### Principios de Diseño
- **Enfoque Pedagógico:** Diagnósticos y mensajes en español rioplatense orientados a facilitar la comprensión de errores conceptuales.
- **Salida Estructurada Dual:** Soporte nativo para visualización enriquecida en terminal (Rich) y salida parseable para orquestadores (`--json`).
- **Integración Contractual:** Capacidad de emitir secciones de reporte para `dredd` (`dredd-section`) y actuar como satélite orquestado por `ripley`.
- **Idempotencia y Robustez:** Validación de precondiciones y comandos de autodiagnóstico (`doctor`) para verificación del entorno.

---

## 2. Instalación y Requisitos

### Requisitos del Sistema
- **Python:** `>= 3.10` (recomendado Python 3.11 o 3.12).
- **Gestor de paquetes:** [`uv`](https://github.com/astral-sh/uv) (entorno estándar de cátedra).
- **Toolchain C (si aplica):** GCC / Clang, Make, GDB y bibliotecas estándar de desarrollo.

### Instalación en el Entorno de Usuario
Para instalar la herramienta de forma global y aislada en el sistema mediante `uv tool`:
```bash
uv tool install --editable /home/mrtin/dev/tools/tetsuo
```

### Verificación de Instalación
Ejecutá el comando `doctor` para constatar que todas las dependencias y binarios requeridos estén presentes y operativos:
```bash
tetsuo doctor
```

---

## 3. Guía Integral de Comandos (CLI)

| Comando | Descripción Breve |
| :--- | :--- |
| [`tetsuo check`](#check) | Compila y ejecuta con AddressSanitizer/UBSan traduciendo cualquier violación a español didáctico. |
| [`tetsuo run`](#run) | Compila y ejecuta con AddressSanitizer/UBSan traduciendo cualquier violación a español didáctico. |
| [`tetsuo report`](#report) | Genera directamente la sección de reporte Markdown de TETSUO para Dredd. |
| [`tetsuo doctor`](#doctor) | Verifica el estado del entorno de sanitizers TETSUO (GCC, Clang, soporte libasan/libubsan). |
| [`tetsuo version`](#version) | Muestra la versión de TETSUO. |

### `tetsuo check`

Compila y ejecuta con AddressSanitizer/UBSan traduciendo cualquier violación a español didáctico.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `target` | `<class 'pathlib._local.Path'>` | Archivo .c o binario a ejecutar bajo sanitizers |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--input`, `-i` | `<class 'str'>` | `` | Entrada estándar (stdin) para la ejecución |
| `--json` | `<class 'bool'>` | `False` | Emitir salida en formato JSON estructurado |
| `--md`, `--output-md` | `Optional[pathlib._local.Path]` | `None` | Generar sección de reporte en formato Markdown para fusión en Dredd. |

#### Ejemplo de Invocación
```bash
tetsuo check <target>
```

### `tetsuo run`

Compila y ejecuta con AddressSanitizer/UBSan traduciendo cualquier violación a español didáctico.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `target` | `<class 'pathlib._local.Path'>` | Archivo .c o binario a ejecutar bajo sanitizers |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--input`, `-i` | `<class 'str'>` | `` | Entrada estándar (stdin) para la ejecución |
| `--json` | `<class 'bool'>` | `False` | Emitir salida en formato JSON estructurado |
| `--md`, `--output-md` | `Optional[pathlib._local.Path]` | `None` | Generar sección de reporte en formato Markdown para fusión en Dredd. |

#### Ejemplo de Invocación
```bash
tetsuo run <target>
```

### `tetsuo report`

Genera directamente la sección de reporte Markdown de TETSUO para Dredd.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `target` | `<class 'pathlib._local.Path'>` | Archivo .c o binario a ejecutar bajo sanitizers |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--output`, `-o` | `Optional[pathlib._local.Path]` | `None` | Ruta de destino del archivo Markdown. |
| `--input`, `-i` | `<class 'str'>` | `` | Entrada estándar para la ejecución |

#### Ejemplo de Invocación
```bash
tetsuo report <target>
```

### `tetsuo doctor`

Verifica el estado del entorno de sanitizers TETSUO (GCC, Clang, soporte libasan/libubsan).

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--json` | `<class 'bool'>` | `False` | Emitir diagnóstico en formato JSON estructurado. |

#### Ejemplo de Invocación
```bash
tetsuo doctor
```

### `tetsuo version`

Muestra la versión de TETSUO.

#### Ejemplo de Invocación
```bash
tetsuo version
```

---

## 4. Formatos de Salida e Integración con el Ecosistema

### Modo Interactivo / Terminal (Rich)
Por defecto, la herramienta renderiza paneles, árboles y tablas estilizadas para facilitar la lectura del estudiante y docente en terminales modernas con soporte ANSI.

### Modo Estructurado JSON (`--json`)
Para integración con pipelines de CI/CD, scripts de automatización u orquestadores externos, la opción `--json` emite un documento JSON estricto por la salida estándar (`stdout`), dirigiendo cualquier mensaje de logging a `stderr`:
```bash
tetsuo check --json
```

### Integración con Dredd (`dredd-section`)
Cuando la herramienta genera reportes de evaluación para entregas de alumnos, produce una sección Markdown estandarizada conforme al contrato de integración de Dredd (v1.0.0):
```markdown
<!-- dredd-section: tetsuo, tool=tetsuo, version=0.1.0, status=ok -->
```
Este encabezado garantiza la agregación determinista de los hallazgos en la rúbrica docente.

### Integración con Ripley
`tetsuo` está registrada en el catálogo de plugins satélites de Ripley (`SATELLITE_CATALOG`). Puede invocarse directamente a través del motor de evaluación de Ripley configurando el análisis en `ripley.toml`.

---

## 5. Diagnóstico y Códigos de Salida

### Códigos de Retorno (`exit code`)
| Código | Significado |
| :---: | :--- |
| `0` | Ejecución exitosa sin hallazgos críticos ni errores de sintaxis. |
| `1` | Hallazgos pedagógicos detectados, infracción de reglas o advertencias activas. |
| `2` | Error de sintaxis en argumentos CLI o archivo fuente no encontrado. |
| `>2` | Error no recuperable del sistema, fallo de memoria o excepción interna. |

### Diagnóstico del Entorno (`doctor`)
Ante comportamientos inesperados, verificá el estado operativo con:
```bash
tetsuo doctor
```
Comprueba la presencia de las dependencias requeridas y la integridad de los componentes del paquete.