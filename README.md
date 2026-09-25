# TETSUO — Traductor y Explicador Pedagógico de Sanitizers (ASan / UBSan)

> 📖 **Manual de Usuario:** Para una guía exhaustiva de comandos, banderas, arquitectura y ejemplos, consultá el [Manual de Uso](MANUAL.md).

**TETSUO** compila y ejecuta programas C bajo AddressSanitizer y UndefinedBehaviorSanitizer, interceptando sus salidas complejas en inglés y traduciéndolas a diagnósticos formativos en español con sugerencias concretas de corrección.

---

## 🎯 Alcance

### Qué cubre
- Compilación instrumentada, ejecución controlada y traducción pedagógica de diagnósticos de sanitizers en programas C.
- Captura y traducción contextual a español rioplatense de advertencias complejas de AddressSanitizer (ASan), UndefinedBehaviorSanitizer (UBSan) y LeakSanitizer (LSan).
- No traduce Valgrind Memcheck, MemorySanitizer ni ThreadSanitizer: solo ASan, UBSan y LSan.
- Identificación de lecturas fuera de límites, accesos tras liberación (use-after-free) y fugas de memoria con indicación precisa de línea y archivo.

### Qué no cubre (Límites y Delegación)
- Confinamiento en sandbox no privilegiado de kernel (delegado a `nostromo`).
- Depuración forense con GDB de core dumps no instrumentados: la cubre `hal`, herramienta complementaria; tetsuo no la invoca ni depende de ella.
- Inyección deliberada de fallos de memoria en runtime (delegado a `vasquez`).

---

## 📋 Requisitos

### Requisitos de Sistema y Entorno
- Linux / WSL o Windows (MSYS2 UCRT64). Python >= 3.10.

### Dependencias Externas y Binarios
- `gcc` o `clang` con bibliotecas de sanitizers (`libasan`, `libubsan`), y `valgrind` (opcional).

### Integración en el Ecosistema
- CLI `tetsuo`. Plugin registrado en `ripley.plugins` (`sanitizer_translator`).

---

## 🚀 Uso Rápido

```bash
# Compilar y ejecutar con sanitizers explicando cualquier fallo
tetsuo run main.c

# Pasar entrada estándar
tetsuo run main.c --input "10\n"

# Salida estructurada JSON
tetsuo run main.c --json
```

---

## 🔬 Errores Diagnosticados

- **`heap-buffer-overflow`**: Desbordamiento en bloques de memoria dinámica (`malloc`).
- **`stack-buffer-overflow`**: Desbordamiento en arrays locales de la pila.
- **`heap-use-after-free`**: Lectura/escritura en punteros ya liberados.
- **`double-free`**: Múltiples llamadas a `free()` sobre la misma dirección.
- **`undefined-behavior`**: Overflows con signo, desreferencia de nulos o shifts inválidos.
