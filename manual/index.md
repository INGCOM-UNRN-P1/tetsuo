---
title: "Manual de Referencia: tetsuo"
subtitle: "Tetsuo — Traductor y Explicador Pedagógico en Español de Sanitizers ASan/UBSan"
author: "Cátedra de Algoritmos y Programación"
date: "2026-08-31"
---

(manual-tetsuo)=
# Tetsuo — Traductor y Explicador Pedagógico en Español de Sanitizers ASan/UBSan

````{abstract}
**Rol en el ecosistema:** Traducción de informes crípticos generados por AddressSanitizer (ASan) y UndefinedBehaviorSanitizer (UBSan) a explicaciones claras en español rioplatense, con diagramas de memoria y sugerencias directas.
````

---

(manual-tetsuo-proposito)=
## 1. Propósito y Filosofía Pedagógica

La herramienta **`tetsuo`** forma parte del ecosistema oficial de software de la cátedra. Su diseño sigue principios pedagógicos rigurosos:

1. **Evidencia Técnica Directa**: Todo diagnóstico se fundamenta en la norma ISO C (C11/C23), en el modelo de memoria del sistema o en convenciones arquitectónicas formales.
2. **Acción Correctiva Concreta**: Cada advertencia incluye la prescripción técnica inmediata para resolver el defecto sin recurrir a conjeturas.
3. **Autonomía del Estudiante**: Facilita la autoevaluación local antes de la entrega final del trabajo práctico.
4. **Objetividad Docente**: Estandariza la corrección automática eliminando discrepancias subjetivas en la evaluación.

---

(manual-tetsuo-instalacion)=
## 2. Instalación y Diagnóstico del Entorno

````{important}
Asegurate de contar con el compilador GCC/Clang y las librerías del sistema instaladas antes de ejecutar `tetsuo`.
````

Para comprobar el estado de salud de tu entorno de trabajo y las dependencias auxiliares:

````{code-block} bash
# Comprobación de dependencias del sistema
tetsuo doctor
````

Si se detecta la falta de alguna utilidad (como `gdb`, `valgrind`, `clang-format` o `typst`), el comando indicará el paquete exacto a instalar según tu distribución GNU/Linux o entorno MSYS2.

---

(manual-tetsuo-comandos)=
## 3. Referencia Completa de Comandos CLI

A continuación se detallan los subcomandos principales disponibles en `tetsuo`:

| Sintaxis del Comando | Descripción y Efecto |
| :--- | :--- |
| `tetsuo run -- ./bin/programa_con_asan` | Ejecuta el binario instrumentado con sanitizers y traduce la salida en tiempo real. |
| `tetsuo translate < asan.log` | Traduce un reporte de error de ASan guardado en un archivo de texto. |
| `tetsuo compile src/*.c -o ./bin/instrumentado` | Compila el código inyectando flags `-fsanitize=address,undefined`. |
| `tetsuo doctor` | Comprueba que GCC/Clang tengan soporte para libasan y libubsan. |

````{tip}
Podés agregar el flag `--json` a la mayoría de los comandos para exportar resultados en formato estructurado o `--md` para generar reportes Markdown para el informe de entrega.
````

---

(manual-tetsuo-tutorial)=
## 4. Tutorial Paso a Paso con Ejemplos Reales

### Caso de Estudio

Considerá el siguiente fragmento de código representativo:

````{code-block} c
:linenos:
#include <stdlib.h>

int main(void) {
    int *vec = malloc(sizeof(int) * 4);
    vec[4] = 42; // Heap-buffer-overflow (índice 4 en tamaño 4: fuera de rango)
    free(vec);
    return 0;
}
````

### Ejecución de la Herramienta

Ejecutá el análisis desde tu terminal:

````{code-block} bash
tetsuo run -- ./bin/programa_con_asan
````

### Salida Obtenida en Consola

````{code-block} text
🚨 DIAGNÓSTICO TETSUO: Heap-Buffer-Overflow (Desborde de Memoria en el Heap)
Ubicación: src/main.c:5 en función 'main()'
Dirección afectada: 0x602000000020 (1 byte después del bloque reservado)

📊 MAPA DE MEMORIA ASAN:
  Bloque asignado: [ 0x602000000010 - 0x60200000001f ] (16 bytes = 4 enteros)
  Intento de escritura en: 0x602000000020 [ZONA PROHIBIDA / REDZONE]

💡 EXPLICACIÓN DIDÁCTICA:
  Reservaste memoria para 4 enteros (índices 0 a 3), pero intentaste escribir en 'vec[4]'.
  En C los arreglos comienzan en el índice 0, por lo que el índice 4 está fuera del bloque permitido.

🔧 SOLUCIÓN:
  Asegurate de que tus lazos y accesos cumplan '0 <= indice < 4'.
````

````{note}
Prestá atención a la explicación pedagógica generada: la herramienta no solo señala la línea del problema, sino que explica la causa raíz y el impacto en memoria o arquitectura.
````

---

(manual-tetsuo-ejercicios)=
## 5. Ejercicios Prácticos y Desafíos

Practicá el uso avanzado de **`tetsuo`** resolviendo los siguientes ejercicios:

````{exercise} Desafío 1: Traducción de Heap-Use-After-Free
Ejecutar un código que accede a memoria liberada y analizar la traducción de Tetsuo.

**Instrucción de ejecución:**
```bash
tetsuo run -- ./bin/use_after_free
```
````

````{solution} Desafío 1
```bash
tetsuo run -- ./bin/use_after_free
# Verificá que la operación concluya exitosamente con código de salida 0.
```
````

````{exercise} Desafío 2: Diagnóstico de Stack-Buffer-Overflow
Identificar desbordes en variables locales del stack.

**Instrucción de ejecución:**
```bash
tetsuo run -- ./bin/stack_overflow
```
````

````{solution} Desafío 2
```bash
tetsuo run -- ./bin/stack_overflow
# Revisá el archivo generado o el informe en terminal para confirmar la resolución del problema.
```
````

````{exercise} Desafío 3: Compilación Instrumentada Rápida
Compilar con sanitizers completos mediante el comando asistido.

**Instrucción de ejecución:**
```bash
tetsuo compile src/main.c -o bin/debug_app
```
````

````{solution} Desafío 3
```bash
tetsuo compile src/main.c -o bin/debug_app
# Comprobá que la salida confirme la ausencia de advertencias o errores pendientes.
```
````

---

(manual-tetsuo-makefile)=
## 6. Integración en el Flujo de Trabajo y Makefile

Para incorporar `tetsuo` de forma automática a tu flujo de desarrollo, agregá la siguiente regla en el `Makefile` de tu proyecto:

````{code-block} makefile
check-tetsuo:
	@echo "=== Ejecutando verificación con tetsuo ==="
	tetsuo check src/ include/

.PHONY: check-tetsuo
````

Ejecutá `make check-tetsuo` antes de cada commit para asegurar que tu código conserve el estado de aprobación.

---

(manual-tetsuo-arquitectura)=
## 7. Arquitectura Interna y Mecanismo Técnico

La herramienta **`tetsuo`** implementa un motor de alta precisión basado en:

- **Tecnología Núcleo:** `LLVM AddressSanitizer / UndefinedBehaviorSanitizer Parser + Shadow Memory Mapper + Spanish Pedagogical Translator`.
- **Aislamiento y Determinismo:** Diseñada para operar sin efectos colaterales en entornos de integración continua (CI), terminales de estudiantes y servidores docentes headless.
- **Manejo de Errores Pedagógico:** Todo fallo de sintaxis, memoria o lógica se traduce en una acción prescriptiva concreta con su respectiva justificación técnica.

---

(manual-tetsuo-ecosistema)=
## 8. Integración y Conexión con el Ecosistema

````{note}
Ninguna herramienta opera de forma aislada. **`tetsuo`** forma parte del pipeline integral de evaluación, verificación y enseñanza de la cátedra.
````

### Diagrama de Flujo e Interoperabilidad

````{mermaid}
graph TD
    DAE[Daedalus: Compilador con Sanitizers] --> BIN[Binario + libasan/libubsan]
    BIN -->|Ejecución con Fuga o UB| ASAN[AddressSanitizer Engine]
    ASAN -->|Reporte Críptico en Inglés| TET[Tetsuo: Traductor Pedagógico]
    TET -->|Mapa de Shadow Memory| TERM[Terminal Estudiante (Español)]
    TET -->|Sección de Sanitizers| DRD[Dredd: Informe alumno_rN.md]
````

### Matriz de Intercambio de Datos

| Canal | Herramientas Conectadas | Tipo de Datos Transferidos |
| :--- | :--- | :--- |
| **Entradas (Inputs)** | - `Salidas de error de ASan/UBSan` | Código fuente, AST, binarios, testcases, contratos |
| **Salidas (Outputs)** | - `hal (correlación de fallas)`
- `dredd (informe en alumno_rN.md)` | Informes Markdown, diagnósticos Rich, JSON, actas |
| **Sincronización** | `daedalus`, `hal`, `nostromo`, `dredd` | Validación cruzada, flags compartidos y autofix |

### Pipeline de Integración Recomendado

Podés encadenar `tetsuo` con otras herramientas del ecosistema en una única línea de comando:

````{code-block} bash
# Pipeline de integración típico
daedalus compile src/*.c -fsanitize=address,undefined -o bin/app && tetsuo run -- ./bin/app
````

