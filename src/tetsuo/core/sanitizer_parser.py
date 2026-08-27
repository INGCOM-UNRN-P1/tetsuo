"""Parser y traductor de diagnósticos crudos de AddressSanitizer y UBSan."""

import re
from typing import List, Optional
from tetsuo.core.models import SanitizerDiagnosis, SanitizerType, SanitizerReport

ASAN_HEADER = re.compile(r'==\d+==ERROR: AddressSanitizer: ([a-zA-Z\-]+) on address ([0-9a-fx]+)')
UBSAN_HEADER = re.compile(r'runtime error: (.*)')
STACK_FRAME = re.compile(r'#0\s+([0-9a-fx]+)\s+in\s+([a-zA-Z0-9_]+)\s+([^:]+):(\d+)')
ACCESS_PATTERN = re.compile(r'(READ|WRITE) of size (\d+)')

CATALOGO_ERRORES = {
    "heap-buffer-overflow": (
        "Desbordamiento de Búfer en el Heap",
        "Tu programa intentó leer o escribir bytes fuera del bloque de memoria dinámica asignado con malloc/calloc.",
        "Verificá los límites de tus bucles al recorrer arrays en Heap y asegurate de multiplicar por sizeof(tipo) al allocar."
    ),
    "stack-buffer-overflow": (
        "Desbordamiento de Búfer en la Pila (Stack)",
        "Tu programa sobrepasó el límite de un array local declarado en el Stack.",
        "Chequeá que los índices de arrays locales no alcancen 'N' (los arreglos en C van de 0 a N-1) y evitá funciones inseguras como gets/strcpy."
    ),
    "global-buffer-overflow": (
        "Desbordamiento de Variable Global",
        "Se accedió fuera de los límites de un array estático o global.",
        "Revisá el tamaño definido en la constante del array global."
    ),
    "heap-use-after-free": (
        "Uso de Memoria tras Liberación (Use-After-Free)",
        "Intentaste leer o escribir en un puntero cuya memoria ya fue liberada con 'free()'.",
        "Asigná 'ptr = NULL;' inmediatamente después de llamar a 'free(ptr)' para prevenir accesos accidentales."
    ),
    "stack-use-after-return": (
        "Uso de Variable de Pila tras Retorno de Función",
        "Una función retornó un puntero a una variable local de su Stack Frame, el cual fue destruido al retornar.",
        "No retornes punteros a variables locales. Asigná la memoria en el Heap con malloc o pasá el búfer como parámetro."
    ),
    "double-free": (
        "Doble Liberación de Memoria (Double Free)",
        "Se invocó 'free()' dos veces sobre la misma dirección de memoria dinámica.",
        "Asegurate de que cada llamada a malloc tenga exactamente una llamada a free."
    ),
}


def parse_sanitizer_output(raw_text: str) -> List[SanitizerDiagnosis]:
    """Parsea texto crudo de stderr y genera diagnósticos pedagógicos estructurados."""
    diagnoses = []

    # 1. AddressSanitizer
    match_asan = ASAN_HEADER.search(raw_text)
    if match_asan:
        tag = match_asan.group(1).lower()
        addr = match_asan.group(2)
        access_match = ACCESS_PATTERN.search(raw_text)
        access_type = access_match.group(1) if access_match else "ACCESO"

        info = CATALOGO_ERRORES.get(tag, (
            f"Fallo de Memoria ({tag})",
            "Error de acceso indebido a memoria detectado por AddressSanitizer.",
            "Revisá la gestión de punteros y memoria dinámica en tu código."
        ))

        # Extraer stack frame superior (#0)
        frame_match = STACK_FRAME.search(raw_text)
        fn_name = frame_match.group(2) if frame_match else "desconocida"
        file_path = frame_match.group(3) if frame_match else None
        line_no = int(frame_match.group(4)) if frame_match else None

        diagnoses.append(SanitizerDiagnosis(
            sanitizer_type=SanitizerType.ASAN,
            error_tag=tag,
            title_es=info[0],
            explanation_es=info[1],
            file_path=file_path,
            line_number=line_no,
            function_name=fn_name,
            memory_address=addr,
            access_type=access_type,
            suggestion_es=info[2],
            raw_snippet=match_asan.group(0)
        ))

    # 2. UndefinedBehaviorSanitizer
    for ubsan_match in UBSAN_HEADER.finditer(raw_text):
        msg = ubsan_match.group(1).strip()
        diagnoses.append(SanitizerDiagnosis(
            sanitizer_type=SanitizerType.UBSAN,
            error_tag="undefined-behavior",
            title_es="Comportamiento Indefinido (Undefined Behavior)",
            explanation_es=f"Se produjo una operación no permitida por el estándar de C: {msg}",
            suggestion_es="Corregí la operación para evitar que el compilador genere código impredecible o erróneo.",
            raw_snippet=ubsan_match.group(0)
        ))

    return diagnoses
