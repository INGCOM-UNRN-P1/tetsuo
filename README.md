# TETSUO — Traductor y Explicador Pedagógico de Sanitizers (ASan / UBSan)

**TETSUO** compila y ejecuta programas C bajo AddressSanitizer y UndefinedBehaviorSanitizer, interceptando sus salidas complejas en inglés y traduciéndolas a diagnósticos formativos en español con sugerencias concretas de corrección.

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
