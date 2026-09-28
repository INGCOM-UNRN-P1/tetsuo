# Changelog

Todos los cambios notables de este proyecto se documentan en este archivo.
Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/);
versiones según [SemVer](https://semver.org/lang/es/).

## [0.2.0] - 2026-09-28

Primera versión con registro de cambios; lo anterior está en el historial de git.

### Agregado

- **cli**: cumplir el contrato de línea de comandos de LINEAMIENTOS §3.2 (N-ECO-04) (`ec98de8`)

### Corregido

- **sanitizers**: no declarar limpio un binario que no fue compilado con sanitizers (N-TETSUO-01) (`af3cf97`)

### Documentación

- agregar el texto de la licencia GPL-3.0-or-later que declara pyproject (N-ECO-06) (`7beb41f`)
- incorporar manual de uso integral y referencia tecnica (tetsuo) (`c1b1ad0`)

### Mantenimiento

- **calidad**: verificar errores de Python y dependencias vulnerables (N-ECO-08, N-ECO-13) (`27c8bba`)
